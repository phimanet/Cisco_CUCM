import json
import os
import re
import shutil
import subprocess
import uuid

try:
    from ldap3 import (
        ALL,
        MODIFY_DELETE,
        MODIFY_REPLACE,
        NTLM,
        SIMPLE,
        SUBTREE,
        Connection,
        Server,
    )
    from ldap3.utils.conv import format_sid

    LDAP3_AVAILABLE = True
except Exception:
    LDAP3_AVAILABLE = False


def _normalize_samaccountname(value):
    sam = (value or "").strip()
    if not sam:
        return ""
    if not re.match(r"^[A-Za-z0-9._-]+$", sam):
        return ""
    return sam


def _format_phone_dashes(phone):
    digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
    if len(digits) == 10:
        return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    return str(phone or "").strip()


def _format_phone_plain(phone):
    return "".join(ch for ch in str(phone or "") if ch.isdigit())


def _resolve_powershell_executable():
    for candidate in ["powershell", "pwsh"]:
        if shutil.which(candidate):
            return candidate
    return ""


def _escape_ldap_filter_value(value):
    escaped = str(value or "")
    escaped = escaped.replace("\\", r"\5c")
    escaped = escaped.replace("*", r"\2a")
    escaped = escaped.replace("(", r"\28")
    escaped = escaped.replace(")", r"\29")
    escaped = escaped.replace("\x00", r"\00")
    return escaped


def _resolve_ldap_config():
    server = (os.getenv("AD_LDAP_SERVER") or "").strip()
    base_dn = (os.getenv("AD_LDAP_BASE_DN") or "").strip()
    if not server or not base_dn:
        return None, "Missing AD_LDAP_SERVER or AD_LDAP_BASE_DN environment configuration"

    use_ssl_raw = (os.getenv("AD_LDAP_USE_SSL") or "true").strip().lower()
    use_ssl = use_ssl_raw in {"1", "true", "yes", "y", "on"}

    port_raw = (os.getenv("AD_LDAP_PORT") or "").strip()
    if port_raw:
        try:
            port = int(port_raw)
        except ValueError:
            return None, "AD_LDAP_PORT must be a valid integer"
    else:
        port = 636 if use_ssl else 389

    auth_mode = (os.getenv("AD_LDAP_AUTH") or "auto").strip().lower()
    default_domain = (os.getenv("AD_LDAP_DOMAIN") or "").strip()
    upn_suffix = (os.getenv("AD_LDAP_UPN_SUFFIX") or "").strip()

    return {
        "server": server,
        "base_dn": base_dn,
        "use_ssl": use_ssl,
        "port": port,
        "auth_mode": auth_mode,
        "default_domain": default_domain,
        "upn_suffix": upn_suffix,
    }, ""


def _resolve_ldap_bind_credentials(auth_context, config):
    username = str((auth_context or {}).get("username") or "").strip()
    password = str((auth_context or {}).get("password") or "")
    if not username or not password:
        return None, None, "LDAP bind requires username and password"

    mode = config["auth_mode"]
    if mode not in {"auto", "ntlm", "simple"}:
        return None, None, "AD_LDAP_AUTH must be auto, ntlm, or simple"

    if mode == "ntlm":
        if "\\" in username:
            return username, NTLM, ""
        if config["default_domain"]:
            return f"{config['default_domain']}\\{username}", NTLM, ""
        return None, None, "NTLM auth selected but username is not DOMAIN\\user and AD_LDAP_DOMAIN is not set"

    if mode == "simple":
        if "@" in username:
            return username, SIMPLE, ""
        if config["upn_suffix"]:
            return f"{username}@{config['upn_suffix']}", SIMPLE, ""
        return username, SIMPLE, ""

    if "\\" in username:
        return username, NTLM, ""
    if "@" in username:
        return username, SIMPLE, ""
    if config["default_domain"]:
        return f"{config['default_domain']}\\{username}", NTLM, ""
    if config["upn_suffix"]:
        return f"{username}@{config['upn_suffix']}", SIMPLE, ""
    return username, SIMPLE, ""


def _run_ldap_lookup(samaccountname, auth_context):
    if not LDAP3_AVAILABLE:
        return None, "ldap3 package is not installed on this server"

    config, config_error = _resolve_ldap_config()
    if config_error:
        return None, config_error

    bind_user, bind_auth, bind_error = _resolve_ldap_bind_credentials(auth_context, config)
    if bind_error:
        return None, bind_error

    try:
        server = Server(
            config["server"],
            port=config["port"],
            use_ssl=config["use_ssl"],
            get_info=ALL,
            connect_timeout=20,
        )
        conn = Connection(
            server,
            user=bind_user,
            password=str((auth_context or {}).get("password") or ""),
            authentication=bind_auth,
            auto_bind=True,
            receive_timeout=20,
        )
    except Exception as exc:
        return None, f"LDAP bind failed: {exc}"

    search_filter = f"(&(objectClass=user)(sAMAccountName={_escape_ldap_filter_value(samaccountname)}))"
    try:
        ok = conn.search(
            search_base=config["base_dn"],
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "telephoneNumber", "ipPhone"],
        )
    except Exception as exc:
        try:
            conn.unbind()
        except Exception:
            pass
        return None, f"LDAP search failed: {exc}"

    if not ok or not conn.entries:
        try:
            conn.unbind()
        except Exception:
            pass
        return {
            "found": False,
            "distinguishedName": "",
            "telephoneNumber": "",
            "ipPhone": "",
        }, ""

    entry = conn.entries[0]
    dn = str(getattr(entry, "entry_dn", "") or "").strip()
    telephone = str(getattr(getattr(entry, "telephoneNumber", None), "value", "") or "").strip()
    ip_phone = str(getattr(getattr(entry, "ipPhone", None), "value", "") or "").strip()

    try:
        conn.unbind()
    except Exception:
        pass

    return {
        "found": True,
        "distinguishedName": dn,
        "telephoneNumber": telephone,
        "ipPhone": ip_phone,
    }, ""


def _run_ldap_modify(distinguished_name, auth_context, replace_attrs=None, clear_attrs=None):
    if not LDAP3_AVAILABLE:
        return "ldap3 package is not installed on this server"

    config, config_error = _resolve_ldap_config()
    if config_error:
        return config_error

    bind_user, bind_auth, bind_error = _resolve_ldap_bind_credentials(auth_context, config)
    if bind_error:
        return bind_error

    try:
        server = Server(
            config["server"],
            port=config["port"],
            use_ssl=config["use_ssl"],
            get_info=ALL,
            connect_timeout=20,
        )
        conn = Connection(
            server,
            user=bind_user,
            password=str((auth_context or {}).get("password") or ""),
            authentication=bind_auth,
            auto_bind=True,
            receive_timeout=20,
        )
    except Exception as exc:
        return f"LDAP bind failed: {exc}"

    changes = {}
    for key, value in (replace_attrs or {}).items():
        changes[key] = [(MODIFY_REPLACE, [value])]
    for key in (clear_attrs or []):
        changes[key] = [(MODIFY_DELETE, [])]

    if not changes:
        try:
            conn.unbind()
        except Exception:
            pass
        return "No LDAP changes were provided"

    try:
        ok = conn.modify(distinguished_name, changes)
    except Exception as exc:
        try:
            conn.unbind()
        except Exception:
            pass
        return f"LDAP modify failed: {exc}"

    result = conn.result or {}
    try:
        conn.unbind()
    except Exception:
        pass

    if not ok:
        desc = str(result.get("description") or "unknown").strip()
        msg = str(result.get("message") or "").strip()
        return f"LDAP modify failed ({desc}): {msg}".strip()

    return ""


def _run_powershell_json(script, payload):
    shell = _resolve_powershell_executable()
    if not shell:
        return None, "PowerShell executable was not found on this server"

    try:
        completed = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", script],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except Exception as exc:
        return None, f"PowerShell execution failed: {exc}"

    if completed.returncode != 0:
        err = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        return None, err or f"PowerShell command failed with exit code {completed.returncode}"

    output = (completed.stdout or "").strip()
    if not output:
        return None, "PowerShell returned no output"

    try:
        return json.loads(output), ""
    except json.JSONDecodeError:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if not lines:
            return None, "PowerShell returned unreadable output"
        try:
            return json.loads(lines[-1]), ""
        except json.JSONDecodeError:
            return None, f"PowerShell did not return JSON output: {lines[-1][:400]}"


def _lookup_ad_user(samaccountname, auth_context):
    payload = {
        "username": (auth_context or {}).get("username", ""),
        "password": (auth_context or {}).get("password", ""),
        "samaccountname": samaccountname,
    }
    script = r"""
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Import-Module ActiveDirectory -ErrorAction Stop

$user = $null
$filterValue = [string]$payload.samaccountname

if ($payload.username -and $payload.password) {
    $secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($payload.username, $secure)
    $user = Get-ADUser -Credential $cred -LDAPFilter "(sAMAccountName=$filterValue)" -Properties telephoneNumber, ipPhone, distinguishedName -ErrorAction Stop
} else {
    $user = Get-ADUser -LDAPFilter "(sAMAccountName=$filterValue)" -Properties telephoneNumber, ipPhone, distinguishedName -ErrorAction Stop
}

if ($null -eq $user) {
    @{ found = $false } | ConvertTo-Json -Compress
    exit 0
}

@{
    found = $true
    distinguishedName = [string]$user.DistinguishedName
    telephoneNumber = [string]$user.telephoneNumber
    ipPhone = [string]$user.ipPhone
} | ConvertTo-Json -Compress
"""

    data, error = _run_powershell_json(script, payload)
    if not error:
        if not isinstance(data, dict):
            return None, "AD lookup returned an invalid response"
        return data, ""

    ldap_data, ldap_error = _run_ldap_lookup(samaccountname, auth_context)
    if ldap_error:
        return None, f"{error}; LDAP fallback failed: {ldap_error}"
    return ldap_data, ""


def update_ad_phone_fields(samaccountname, phone_number, auth_context=None):
    sam = _normalize_samaccountname(samaccountname)
    if not sam:
        return False, "Invalid or empty AD samAccountName"

    formatted_dash = _format_phone_dashes(phone_number)
    formatted_plain = _format_phone_plain(phone_number)
    if not formatted_plain:
        return False, "Phone number must contain digits"

    user_data, lookup_error = _lookup_ad_user(sam, auth_context)
    if lookup_error:
        return False, f"AD lookup failed for {sam}: {lookup_error}"
    if not user_data.get("found"):
        return False, f"AD user {sam} was not found"

    payload = {
        "username": (auth_context or {}).get("username", ""),
        "password": (auth_context or {}).get("password", ""),
        "distinguishedName": user_data.get("distinguishedName", ""),
        "telephoneNumber": formatted_dash,
        "ipPhone": formatted_plain,
    }
    script = r"""
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Import-Module ActiveDirectory -ErrorAction Stop

if (-not $payload.distinguishedName) {
    throw "AD distinguishedName was not provided"
}

if ($payload.username -and $payload.password) {
    $secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($payload.username, $secure)
    Set-ADUser -Credential $cred -Identity $payload.distinguishedName -Replace @{ telephoneNumber = $payload.telephoneNumber; ipPhone = $payload.ipPhone } -ErrorAction Stop
} else {
    Set-ADUser -Identity $payload.distinguishedName -Replace @{ telephoneNumber = $payload.telephoneNumber; ipPhone = $payload.ipPhone } -ErrorAction Stop
}

@{ success = $true } | ConvertTo-Json -Compress
"""

    _, update_error = _run_powershell_json(script, payload)
    if update_error:
        ldap_error = _run_ldap_modify(
            user_data.get("distinguishedName", ""),
            auth_context,
            replace_attrs={
                "telephoneNumber": formatted_dash,
                "ipPhone": formatted_plain,
            },
        )
        if ldap_error:
            return False, f"AD update failed for {sam}: {update_error}; LDAP fallback failed: {ldap_error}"

    return True, f"Updated AD phone fields for {sam} (telephoneNumber={formatted_dash}, ipPhone={formatted_plain})"


def clear_ad_phone_fields(samaccountname, auth_context=None):
    sam = _normalize_samaccountname(samaccountname)
    if not sam:
        return False, "Invalid or empty AD samAccountName"

    user_data, lookup_error = _lookup_ad_user(sam, auth_context)
    if lookup_error:
        return False, f"AD lookup failed for {sam}: {lookup_error}"
    if not user_data.get("found"):
        return False, f"AD user {sam} was not found"

    payload = {
        "username": (auth_context or {}).get("username", ""),
        "password": (auth_context or {}).get("password", ""),
        "distinguishedName": user_data.get("distinguishedName", ""),
    }
    script = r"""
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Import-Module ActiveDirectory -ErrorAction Stop

if (-not $payload.distinguishedName) {
    throw "AD distinguishedName was not provided"
}

if ($payload.username -and $payload.password) {
    $secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($payload.username, $secure)
    Set-ADUser -Credential $cred -Identity $payload.distinguishedName -Clear telephoneNumber, ipPhone -ErrorAction Stop
} else {
    Set-ADUser -Identity $payload.distinguishedName -Clear telephoneNumber, ipPhone -ErrorAction Stop
}

@{ success = $true } | ConvertTo-Json -Compress
"""

    _, clear_error = _run_powershell_json(script, payload)
    if clear_error:
        ldap_error = _run_ldap_modify(
            user_data.get("distinguishedName", ""),
            auth_context,
            clear_attrs=["telephoneNumber", "ipPhone"],
        )
        if ldap_error:
            return False, f"AD clear failed for {sam}: {clear_error}; LDAP fallback failed: {ldap_error}"

    return True, f"Cleared AD phone fields for {sam}"


def _normalize_group_lookup_name(value):
    return str(value or "").strip()


def _group_scope_from_group_type(group_type_value):
    try:
        raw = int(group_type_value)
    except Exception:
        return ""

    normalized = raw & 0xFFFFFFFF
    scope_bits = normalized & 0x0000000E
    if scope_bits == 0x00000002:
        return "Global"
    if scope_bits == 0x00000004:
        return "DomainLocal"
    if scope_bits == 0x00000008:
        return "Universal"
    return ""


def _group_category_from_group_type(group_type_value):
    try:
        raw = int(group_type_value)
    except Exception:
        return ""

    normalized = raw & 0xFFFFFFFF
    return "Security" if (normalized & 0x80000000) else "Distribution"


def _guid_to_string(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            return str(uuid.UUID(bytes_le=bytes(value)))
        except Exception:
            try:
                return str(uuid.UUID(bytes=bytes(value)))
            except Exception:
                return ""
    return str(value).strip()


def _sid_to_string(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (bytes, bytearray)):
        try:
            return format_sid(bytes(value))
        except Exception:
            return ""
    return str(value).strip()


def _lookup_ad_group_powershell(group_name, auth_context):
    payload = {
        "username": (auth_context or {}).get("username", ""),
        "password": (auth_context or {}).get("password", ""),
        "group_name": group_name,
    }
    script = r"""
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Import-Module ActiveDirectory -ErrorAction Stop

$groupName = [string]$payload.group_name
$group = $null

if ($payload.username -and $payload.password) {
    $secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($payload.username, $secure)
    $group = Get-ADGroup -Credential $cred -Filter "Name -eq '$groupName'" -Properties DistinguishedName,ObjectGUID,SID,GroupCategory,GroupScope,Name,SamAccountName -ErrorAction Stop
} else {
    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties DistinguishedName,ObjectGUID,SID,GroupCategory,GroupScope,Name,SamAccountName -ErrorAction Stop
}

if ($null -eq $group) {
    @{ found = $false } | ConvertTo-Json -Compress
    exit 0
}

@{
    found = $true
    name = [string]$group.Name
    samAccountName = [string]$group.SamAccountName
    distinguishedName = [string]$group.DistinguishedName
    objectGUID = [string]$group.ObjectGUID
    sid = [string]$group.SID
    groupCategory = [string]$group.GroupCategory
    groupScope = [string]$group.GroupScope
} | ConvertTo-Json -Compress
"""

    data, error = _run_powershell_json(script, payload)
    if error:
        return None, error
    if not isinstance(data, dict):
        return None, "AD group lookup returned an invalid response"
    return data, ""


def _lookup_ad_group_ldap(group_name, auth_context):
    if not LDAP3_AVAILABLE:
        return None, "ldap3 package is not installed on this server"

    config, config_error = _resolve_ldap_config()
    if config_error:
        return None, config_error

    bind_user, bind_auth, bind_error = _resolve_ldap_bind_credentials(auth_context, config)
    if bind_error:
        return None, bind_error

    try:
        server = Server(
            config["server"],
            port=config["port"],
            use_ssl=config["use_ssl"],
            get_info=ALL,
            connect_timeout=20,
        )
        conn = Connection(
            server,
            user=bind_user,
            password=str((auth_context or {}).get("password") or ""),
            authentication=bind_auth,
            auto_bind=True,
            receive_timeout=20,
        )
    except Exception as exc:
        return None, f"LDAP bind failed: {exc}"

    escaped = _escape_ldap_filter_value(group_name)
    search_filter = (
        f"(&(objectClass=group)(|"
        f"(cn={escaped})"
        f"(name={escaped})"
        f"(sAMAccountName={escaped})"
        "))"
    )

    try:
        ok = conn.search(
            search_base=config["base_dn"],
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                "distinguishedName",
                "cn",
                "name",
                "sAMAccountName",
                "objectGUID",
                "objectSid",
                "groupType",
            ],
        )
    except Exception as exc:
        try:
            conn.unbind()
        except Exception:
            pass
        return None, f"LDAP search failed: {exc}"

    if not ok or not conn.entries:
        try:
            conn.unbind()
        except Exception:
            pass
        return {"found": False}, ""

    entry = conn.entries[0]
    dn = str(getattr(entry, "entry_dn", "") or "").strip()
    name = str(getattr(getattr(entry, "name", None), "value", "") or getattr(getattr(entry, "cn", None), "value", "") or "").strip()
    sam = str(getattr(getattr(entry, "sAMAccountName", None), "value", "") or "").strip()
    guid = _guid_to_string(getattr(getattr(entry, "objectGUID", None), "value", None))
    sid = _sid_to_string(getattr(getattr(entry, "objectSid", None), "value", None))
    group_type = getattr(getattr(entry, "groupType", None), "value", None)
    category = _group_category_from_group_type(group_type)
    scope = _group_scope_from_group_type(group_type)

    try:
        conn.unbind()
    except Exception:
        pass

    return {
        "found": True,
        "name": name,
        "samAccountName": sam,
        "distinguishedName": dn,
        "objectGUID": guid,
        "sid": sid,
        "groupCategory": category,
        "groupScope": scope,
    }, ""


def inspect_ad_group_identifiers(group_name, auth_context=None):
    clean_name = _normalize_group_lookup_name(group_name)
    if not clean_name:
        return None, "group_name is required"

    ps_data, ps_error = _lookup_ad_group_powershell(clean_name, auth_context)
    if not ps_error and isinstance(ps_data, dict):
        result = dict(ps_data)
        result["query"] = clean_name
        result["source"] = "powershell"
        return result, ""

    ldap_data, ldap_error = _lookup_ad_group_ldap(clean_name, auth_context)
    if not ldap_error and isinstance(ldap_data, dict):
        result = dict(ldap_data)
        result["query"] = clean_name
        result["source"] = "ldap"
        return result, ""

    if ps_error and ldap_error:
        return None, f"{ps_error}; LDAP fallback failed: {ldap_error}"
    return None, ps_error or ldap_error or "AD group lookup failed"
import json
import os
import re
import shutil
import subprocess
import uuid
import base64

try:
    from ldap3 import (
        ALL,
        MODIFY_ADD,
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
    candidates = [
        "powershell",
        "pwsh",
        "/usr/bin/pwsh",
        "/usr/local/bin/pwsh",
        "/opt/microsoft/powershell/7/pwsh",
        "/usr/bin/powershell",
        "/usr/local/bin/powershell",
    ]
    for candidate in candidates:
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return ""


def _resolve_ldapsearch_executable():
    candidates = [
        "ldapsearch",
        "/usr/bin/ldapsearch",
        "/usr/local/bin/ldapsearch",
        "/bin/ldapsearch",
        "/usr/sbin/ldapsearch",
    ]
    for candidate in candidates:
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return ""


def _resolve_ldapmodify_executable():
    candidates = [
        "ldapmodify",
        "/usr/bin/ldapmodify",
        "/usr/local/bin/ldapmodify",
        "/bin/ldapmodify",
        "/usr/sbin/ldapmodify",
    ]
    for candidate in candidates:
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
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
    if not ldap_error and isinstance(ldap_data, dict):
        return ldap_data, ""

    ldapsearch_data, ldapsearch_error = _lookup_ad_user_ldapsearch(samaccountname, auth_context)
    if not ldapsearch_error and isinstance(ldapsearch_data, dict):
        return ldapsearch_data, ""

    if ldap_error and ldapsearch_error:
        return None, f"{error}; LDAP fallback failed: {ldap_error}; ldapsearch fallback failed: {ldapsearch_error}"
    return None, f"{error}; LDAP fallback failed: {ldap_error or ldapsearch_error}"


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
            ldapsearch_error = _run_ldapmodify_attributes(
                user_data.get("distinguishedName", ""),
                auth_context,
                replace_attrs={
                    "telephoneNumber": formatted_dash,
                    "ipPhone": formatted_plain,
                },
            )
            if ldapsearch_error:
                return False, f"AD update failed for {sam}: {update_error}; LDAP fallback failed: {ldap_error}; ldapsearch fallback failed: {ldapsearch_error}"

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
            ldapsearch_error = _run_ldapmodify_attributes(
                user_data.get("distinguishedName", ""),
                auth_context,
                clear_attrs=["telephoneNumber", "ipPhone"],
            )
            if ldapsearch_error:
                return False, f"AD clear failed for {sam}: {clear_error}; LDAP fallback failed: {ldap_error}; ldapsearch fallback failed: {ldapsearch_error}"

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

    ldapsearch_data, ldapsearch_error = _lookup_ad_group_ldapsearch(clean_name, auth_context)
    if not ldapsearch_error and isinstance(ldapsearch_data, dict):
        result = dict(ldapsearch_data)
        result["query"] = clean_name
        result["source"] = "ldapsearch"
        return result, ""

    if ps_error and ldap_error and ldapsearch_error:
        return None, f"{ps_error}; LDAP fallback failed: {ldap_error}; ldapsearch fallback failed: {ldapsearch_error}"
    return None, ps_error or ldap_error or ldapsearch_error or "AD group lookup failed"


def _normalize_membership_action(value):
    action = str(value or "").strip().lower()
    if action in {"check", "add", "remove"}:
        return action
    return ""


def _manage_ad_group_membership_powershell(samaccountname, group_name, action, auth_context):
    payload = {
        "username": (auth_context or {}).get("username", ""),
        "password": (auth_context or {}).get("password", ""),
        "samaccountname": samaccountname,
        "group_name": group_name,
        "action": action,
    }
    script = r"""
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Import-Module ActiveDirectory -ErrorAction Stop

$sam = [string]$payload.samaccountname
$groupName = [string]$payload.group_name
$action = ([string]$payload.action).ToLowerInvariant()

$cred = $null
if ($payload.username -and $payload.password) {
    $secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
    $cred = [System.Management.Automation.PSCredential]::new($payload.username, $secure)
}

if ($cred) {
    $user = Get-ADUser -Credential $cred -LDAPFilter "(sAMAccountName=$sam)" -Properties distinguishedName,memberOf -ErrorAction SilentlyContinue
    $group = Get-ADGroup -Credential $cred -Filter "Name -eq '$groupName'" -Properties distinguishedName,name,samAccountName -ErrorAction SilentlyContinue
} else {
    $user = Get-ADUser -LDAPFilter "(sAMAccountName=$sam)" -Properties distinguishedName,memberOf -ErrorAction SilentlyContinue
    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties distinguishedName,name,samAccountName -ErrorAction SilentlyContinue
}

if ($null -eq $user) {
    @{ ok = $false; userFound = $false; groupFound = ($null -ne $group); message = "AD user '$sam' was not found" } | ConvertTo-Json -Compress
    exit 0
}

if ($null -eq $group) {
    @{ ok = $false; userFound = $true; groupFound = $false; message = "AD group '$groupName' was not found" } | ConvertTo-Json -Compress
    exit 0
}

$groupDn = [string]$group.DistinguishedName
$userDn = [string]$user.DistinguishedName
$isMember = $false
if ($user.memberOf) {
    foreach ($dn in @($user.memberOf)) {
        if ([string]::Equals([string]$dn, $groupDn, [System.StringComparison]::OrdinalIgnoreCase)) {
            $isMember = $true
            break
        }
    }
}

$changed = $false
$message = ""

if ($action -eq "add") {
    if (-not $isMember) {
        if ($cred) {
            Add-ADGroupMember -Credential $cred -Identity $groupDn -Members $userDn -ErrorAction Stop
            $user = Get-ADUser -Credential $cred -Identity $userDn -Properties memberOf -ErrorAction Stop
        } else {
            Add-ADGroupMember -Identity $groupDn -Members $userDn -ErrorAction Stop
            $user = Get-ADUser -Identity $userDn -Properties memberOf -ErrorAction Stop
        }

        $isMember = $false
        if ($user.memberOf) {
            foreach ($dn in @($user.memberOf)) {
                if ([string]::Equals([string]$dn, $groupDn, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $isMember = $true
                    break
                }
            }
        }

        $changed = $isMember
        $message = if ($isMember) { "User added to group" } else { "Add requested but membership could not be confirmed" }
    } else {
        $message = "User is already a member"
    }
} elseif ($action -eq "remove") {
    if ($isMember) {
        if ($cred) {
            Remove-ADGroupMember -Credential $cred -Identity $groupDn -Members $userDn -Confirm:$false -ErrorAction Stop
            $user = Get-ADUser -Credential $cred -Identity $userDn -Properties memberOf -ErrorAction Stop
        } else {
            Remove-ADGroupMember -Identity $groupDn -Members $userDn -Confirm:$false -ErrorAction Stop
            $user = Get-ADUser -Identity $userDn -Properties memberOf -ErrorAction Stop
        }

        $isMember = $false
        if ($user.memberOf) {
            foreach ($dn in @($user.memberOf)) {
                if ([string]::Equals([string]$dn, $groupDn, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $isMember = $true
                    break
                }
            }
        }

        $changed = -not $isMember
        $message = if (-not $isMember) { "User removed from group" } else { "Remove requested but membership still present" }
    } else {
        $message = "User is not currently a member"
    }
} else {
    $message = if ($isMember) { "User is currently a member" } else { "User is not currently a member" }
}

@{
    ok = $true
    action = $action
    changed = $changed
    userFound = $true
    groupFound = $true
    userSamAccountName = $sam
    userDistinguishedName = $userDn
    groupName = [string]$group.Name
    groupSamAccountName = [string]$group.SamAccountName
    groupDistinguishedName = $groupDn
    isMember = $isMember
    message = $message
} | ConvertTo-Json -Compress
"""

    data, error = _run_powershell_json(script, payload)
    if error:
        return None, error
    if not isinstance(data, dict):
        return None, "AD group membership operation returned an invalid response"
    return data, ""


def _manage_ad_group_membership_ldap(samaccountname, group_name, action, auth_context):
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

    try:
        user_filter = f"(&(objectClass=user)(sAMAccountName={_escape_ldap_filter_value(samaccountname)}))"
        ok_user = conn.search(
            search_base=config["base_dn"],
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "sAMAccountName", "memberOf"],
        )
        if not ok_user or not conn.entries:
            return {
                "ok": False,
                "action": action,
                "changed": False,
                "userFound": False,
                "groupFound": True,
                "isMember": False,
                "message": f"AD user '{samaccountname}' was not found",
            }, ""

        user_entry = conn.entries[0]
        user_dn = str(getattr(user_entry, "entry_dn", "") or "").strip()
        user_sam = str(getattr(getattr(user_entry, "sAMAccountName", None), "value", samaccountname) or samaccountname).strip()
        member_of_values = [str(v or "").strip().lower() for v in (getattr(getattr(user_entry, "memberOf", None), "values", []) or [])]

        group_filter = (
            f"(&(objectClass=group)(|"
            f"(cn={_escape_ldap_filter_value(group_name)})"
            f"(name={_escape_ldap_filter_value(group_name)})"
            f"(sAMAccountName={_escape_ldap_filter_value(group_name)})"
            f"))"
        )
        ok_group = conn.search(
            search_base=config["base_dn"],
            search_filter=group_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "cn", "name", "sAMAccountName"],
        )
        if not ok_group or not conn.entries:
            return {
                "ok": False,
                "action": action,
                "changed": False,
                "userFound": True,
                "groupFound": False,
                "isMember": False,
                "userSamAccountName": user_sam,
                "userDistinguishedName": user_dn,
                "message": f"AD group '{group_name}' was not found",
            }, ""

        group_entry = conn.entries[0]
        group_dn = str(getattr(group_entry, "entry_dn", "") or "").strip()
        group_name_value = str(
            getattr(getattr(group_entry, "name", None), "value", "")
            or getattr(getattr(group_entry, "cn", None), "value", "")
            or group_name
        ).strip()
        group_sam = str(getattr(getattr(group_entry, "sAMAccountName", None), "value", "") or "").strip()

        is_member = group_dn.lower() in member_of_values
        changed = False
        message = ""

        if action == "add":
            if is_member:
                message = "User is already a member"
            else:
                ok_modify = conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
                if not ok_modify:
                    result = conn.result or {}
                    desc = str(result.get("description") or "unknown").strip()
                    msg = str(result.get("message") or "").strip()
                    return None, f"LDAP add membership failed ({desc}): {msg}".strip()
                changed = True
                message = "User added to group"
        elif action == "remove":
            if not is_member:
                message = "User is not currently a member"
            else:
                ok_modify = conn.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
                if not ok_modify:
                    result = conn.result or {}
                    desc = str(result.get("description") or "unknown").strip()
                    msg = str(result.get("message") or "").strip()
                    return None, f"LDAP remove membership failed ({desc}): {msg}".strip()
                changed = True
                message = "User removed from group"
        else:
            message = "User is currently a member" if is_member else "User is not currently a member"

        # Re-check membership after any attempted modification.
        conn.search(
            search_base=config["base_dn"],
            search_filter=user_filter,
            search_scope=SUBTREE,
            attributes=["memberOf"],
        )
        if conn.entries:
            refreshed = conn.entries[0]
            refreshed_member_of = [
                str(v or "").strip().lower()
                for v in (getattr(getattr(refreshed, "memberOf", None), "values", []) or [])
            ]
            is_member = group_dn.lower() in refreshed_member_of

        return {
            "ok": True,
            "action": action,
            "changed": changed,
            "userFound": True,
            "groupFound": True,
            "userSamAccountName": user_sam,
            "userDistinguishedName": user_dn,
            "groupName": group_name_value,
            "groupSamAccountName": group_sam,
            "groupDistinguishedName": group_dn,
            "isMember": is_member,
            "message": message,
        }, ""
    except Exception as exc:
        return None, f"LDAP membership operation failed: {exc}"
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _ldap_uri_candidates(config):
    primary_scheme = "ldaps" if bool((config or {}).get("use_ssl")) else "ldap"
    primary_port = int((config or {}).get("port") or (636 if primary_scheme == "ldaps" else 389))
    candidates = [f"{primary_scheme}://{config.get('server')}:{primary_port}"]
    if primary_scheme == "ldaps":
        candidates.append(f"ldap://{config.get('server')}:389")
    else:
        candidates.append(f"ldaps://{config.get('server')}:636")
    return candidates


def _ldif_value_to_text(value):
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""
    return str(value or "").strip()


def _first_attr_value(attrs, keys):
    for key in keys:
        values = attrs.get(key) or []
        if not values:
            continue
        for value in values:
            text = _ldif_value_to_text(value)
            if text:
                return text
    return ""


def _attr_values_lower(attrs, key):
    values = attrs.get(key) or []
    out = []
    for value in values:
        text = _ldif_value_to_text(value)
        if text:
            out.append(text.lower())
    return out


def _run_ldapsearch_query(config, bind_user, password, search_filter, attributes):
    ldapsearch_bin = _resolve_ldapsearch_executable()
    if not ldapsearch_bin:
        return None, "ldapsearch executable was not found on this server"

    last_error = ""
    completed = None
    for uri in _ldap_uri_candidates(config):
        cmd = [
            ldapsearch_bin,
            "-LLL",
            "-x",
            "-o",
            "nettimeout=8",
            "-o",
            "TLS_REQCERT=never",
            "-H",
            uri,
            "-D",
            bind_user,
            "-w",
            password,
            "-b",
            str(config.get("base_dn") or ""),
            search_filter,
        ]
        cmd.extend(attributes or [])

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except Exception as exc:
            last_error = f"ldapsearch execution failed: {exc}"
            continue

        if completed.returncode == 0:
            return _parse_ldif_attributes(completed.stdout or ""), ""

        error_text = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        last_error = f"{uri}: {error_text or f'ldapsearch failed with exit code {completed.returncode}'}"

    return None, last_error or "ldapsearch failed"


def _run_ldapmodify_membership(config, bind_user, password, group_dn, user_dn, action):
    ldapmodify_bin = _resolve_ldapmodify_executable()
    if not ldapmodify_bin:
        return "ldapmodify executable was not found on this server"

    if action not in {"add", "remove"}:
        return "ldapmodify action must be add or remove"

    op = "add" if action == "add" else "delete"
    ldif = (
        f"dn: {group_dn}\n"
        "changetype: modify\n"
        f"{op}: member\n"
        f"member: {user_dn}\n"
        "-\n"
    )

    last_error = ""
    for uri in _ldap_uri_candidates(config):
        cmd = [
            ldapmodify_bin,
            "-x",
            "-o",
            "nettimeout=8",
            "-o",
            "TLS_REQCERT=never",
            "-H",
            uri,
            "-D",
            bind_user,
            "-w",
            password,
        ]

        try:
            completed = subprocess.run(
                cmd,
                input=ldif,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except Exception as exc:
            last_error = f"ldapmodify execution failed: {exc}"
            continue

        if completed.returncode == 0:
            return ""

        error_text = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        normalized = error_text.lower()
        if action == "add" and ("type or value exists" in normalized or "attribute or value exists" in normalized):
            return ""
        if action == "remove" and ("no such attribute" in normalized or "can't delete" in normalized):
            return ""

        last_error = f"{uri}: {error_text or f'ldapmodify failed with exit code {completed.returncode}'}"

    return last_error or "ldapmodify failed"


def _run_ldapmodify_attributes(distinguished_name, auth_context, replace_attrs=None, clear_attrs=None):
    dn = str(distinguished_name or "").strip()
    if not dn:
        return "AD distinguishedName was not provided"

    config, config_error = _resolve_ldap_config()
    if config_error:
        return config_error

    password = str((auth_context or {}).get("password") or "")
    if not password:
        return "LDAP bind requires username and password"

    bind_user = _resolve_ldapsearch_bind_user(auth_context, config)
    if not bind_user:
        return "LDAP bind requires username"

    ldapmodify_bin = _resolve_ldapmodify_executable()
    if not ldapmodify_bin:
        return "ldapmodify executable was not found on this server"

    lines = [f"dn: {dn}", "changetype: modify"]
    for key, value in (replace_attrs or {}).items():
        attr = str(key or "").strip()
        if not attr:
            continue
        lines.append(f"replace: {attr}")
        lines.append(f"{attr}: {str(value or '').strip()}")
        lines.append("-")
    for key in (clear_attrs or []):
        attr = str(key or "").strip()
        if not attr:
            continue
        lines.append(f"delete: {attr}")
        lines.append("-")

    if len(lines) <= 2:
        return "No LDAP changes were provided"

    ldif = "\n".join(lines) + "\n"

    last_error = ""
    for uri in _ldap_uri_candidates(config):
        cmd = [
            ldapmodify_bin,
            "-x",
            "-o",
            "nettimeout=8",
            "-o",
            "TLS_REQCERT=never",
            "-H",
            uri,
            "-D",
            bind_user,
            "-w",
            password,
        ]

        try:
            completed = subprocess.run(
                cmd,
                input=ldif,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except Exception as exc:
            last_error = f"ldapmodify execution failed: {exc}"
            continue

        if completed.returncode == 0:
            return ""

        error_text = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        last_error = f"{uri}: {error_text or f'ldapmodify failed with exit code {completed.returncode}'}"

    return last_error or "ldapmodify failed"


def _lookup_ad_user_ldapsearch(samaccountname, auth_context):
    config, config_error = _resolve_ldap_config()
    if config_error:
        return None, config_error

    password = str((auth_context or {}).get("password") or "")
    if not password:
        return None, "LDAP bind requires username and password"

    bind_user = _resolve_ldapsearch_bind_user(auth_context, config)
    if not bind_user:
        return None, "LDAP bind requires username"

    search_filter = f"(&(objectClass=user)(sAMAccountName={_escape_ldap_filter_value(samaccountname)}))"
    attrs, lookup_error = _run_ldapsearch_query(
        config,
        bind_user,
        password,
        search_filter,
        ["distinguishedName", "telephoneNumber", "ipPhone", "sAMAccountName"],
    )
    if lookup_error:
        return None, lookup_error

    dn = _first_attr_value(attrs or {}, ["distinguishedName", "dn"])
    if not dn:
        return {
            "found": False,
            "distinguishedName": "",
            "telephoneNumber": "",
            "ipPhone": "",
        }, ""

    return {
        "found": True,
        "distinguishedName": dn,
        "telephoneNumber": _first_attr_value(attrs or {}, ["telephoneNumber"]),
        "ipPhone": _first_attr_value(attrs or {}, ["ipPhone"]),
    }, ""


def _manage_ad_group_membership_ldapsearch(samaccountname, group_name, action, auth_context):
    config, config_error = _resolve_ldap_config()
    if config_error:
        return None, config_error

    password = str((auth_context or {}).get("password") or "")
    if not password:
        return None, "LDAP bind requires username and password"

    bind_user = _resolve_ldapsearch_bind_user(auth_context, config)
    if not bind_user:
        return None, "LDAP bind requires username"

    user_filter = f"(&(objectClass=user)(sAMAccountName={_escape_ldap_filter_value(samaccountname)}))"
    user_attrs, user_error = _run_ldapsearch_query(
        config,
        bind_user,
        password,
        user_filter,
        ["distinguishedName", "sAMAccountName", "memberOf"],
    )
    if user_error:
        return None, user_error

    user_dn = _first_attr_value(user_attrs or {}, ["distinguishedName", "dn"])
    user_sam = _first_attr_value(user_attrs or {}, ["sAMAccountName", "samAccountName"]) or samaccountname
    if not user_dn:
        return {
            "ok": False,
            "action": action,
            "changed": False,
            "userFound": False,
            "groupFound": True,
            "isMember": False,
            "message": f"AD user '{samaccountname}' was not found",
        }, ""

    group_filter = (
        f"(&(objectClass=group)(|"
        f"(cn={_escape_ldap_filter_value(group_name)})"
        f"(name={_escape_ldap_filter_value(group_name)})"
        f"(sAMAccountName={_escape_ldap_filter_value(group_name)})"
        "))"
    )
    group_attrs, group_error = _run_ldapsearch_query(
        config,
        bind_user,
        password,
        group_filter,
        ["distinguishedName", "cn", "name", "sAMAccountName"],
    )
    if group_error:
        return None, group_error

    group_dn = _first_attr_value(group_attrs or {}, ["distinguishedName", "dn"])
    group_name_value = _first_attr_value(group_attrs or {}, ["name", "cn"]) or group_name
    group_sam = _first_attr_value(group_attrs or {}, ["sAMAccountName", "samAccountName"])
    if not group_dn:
        return {
            "ok": False,
            "action": action,
            "changed": False,
            "userFound": True,
            "groupFound": False,
            "isMember": False,
            "userSamAccountName": user_sam,
            "userDistinguishedName": user_dn,
            "message": f"AD group '{group_name}' was not found",
        }, ""

    member_of_values = _attr_values_lower(user_attrs or {}, "memberOf")
    is_member = group_dn.lower() in member_of_values
    changed = False
    message = ""

    if action == "add":
        if is_member:
            message = "User is already a member"
        else:
            modify_error = _run_ldapmodify_membership(config, bind_user, password, group_dn, user_dn, "add")
            if modify_error:
                return None, f"LDAP add membership failed: {modify_error}"
            changed = True
            message = "User added to group"
    elif action == "remove":
        if not is_member:
            message = "User is not currently a member"
        else:
            modify_error = _run_ldapmodify_membership(config, bind_user, password, group_dn, user_dn, "remove")
            if modify_error:
                return None, f"LDAP remove membership failed: {modify_error}"
            changed = True
            message = "User removed from group"
    else:
        message = "User is currently a member" if is_member else "User is not currently a member"

    # Re-check membership after modification to return final state.
    refreshed_user_attrs, refreshed_error = _run_ldapsearch_query(
        config,
        bind_user,
        password,
        user_filter,
        ["memberOf"],
    )
    if not refreshed_error and isinstance(refreshed_user_attrs, dict):
        refreshed_member_of = _attr_values_lower(refreshed_user_attrs, "memberOf")
        is_member = group_dn.lower() in refreshed_member_of

    return {
        "ok": True,
        "action": action,
        "changed": changed,
        "userFound": True,
        "groupFound": True,
        "userSamAccountName": user_sam,
        "userDistinguishedName": user_dn,
        "groupName": group_name_value,
        "groupSamAccountName": group_sam,
        "groupDistinguishedName": group_dn,
        "isMember": is_member,
        "message": message,
    }, ""


def manage_ad_group_membership(samaccountname, group_name, action, auth_context=None):
    sam = _normalize_samaccountname(samaccountname)
    if not sam:
        return False, None, "Invalid or empty AD samAccountName"

    clean_group = _normalize_group_lookup_name(group_name)
    if not clean_group:
        return False, None, "group_name is required"

    normalized_action = _normalize_membership_action(action)
    if not normalized_action:
        return False, None, "action must be one of: check, add, remove"

    ps_data, ps_error = _manage_ad_group_membership_powershell(sam, clean_group, normalized_action, auth_context)
    if not ps_error and isinstance(ps_data, dict):
        result = dict(ps_data)
        result["source"] = "powershell"
        return bool(result.get("ok")), result, ""

    ldap_data, ldap_error = _manage_ad_group_membership_ldap(sam, clean_group, normalized_action, auth_context)
    if not ldap_error and isinstance(ldap_data, dict):
        result = dict(ldap_data)
        result["source"] = "ldap"
        return bool(result.get("ok")), result, ""

    ldapsearch_data, ldapsearch_error = _manage_ad_group_membership_ldapsearch(sam, clean_group, normalized_action, auth_context)
    if not ldapsearch_error and isinstance(ldapsearch_data, dict):
        result = dict(ldapsearch_data)
        result["source"] = "ldapsearch"
        return bool(result.get("ok")), result, ""

    if ps_error and ldap_error and ldapsearch_error:
        return False, None, f"{ps_error}; LDAP fallback failed: {ldap_error}; ldapsearch fallback failed: {ldapsearch_error}"
    return False, None, ps_error or ldap_error or ldapsearch_error or "AD group membership operation failed"


def _resolve_ldapsearch_bind_user(auth_context, config):
    username = str((auth_context or {}).get("username") or "").strip()
    if not username:
        return ""

    if "@" in username:
        return username

    if "\\" in username:
        username = username.split("\\", 1)[-1].strip()

    upn_suffix = str((config or {}).get("upn_suffix") or "").strip()
    if upn_suffix:
        return f"{username}@{upn_suffix}"

    default_domain = str((config or {}).get("default_domain") or "").strip()
    if default_domain and "." in default_domain:
        return f"{username}@{default_domain}"

    return username


def _parse_ldif_attributes(output_text):
    lines = str(output_text or "").splitlines()
    unfolded = []
    for line in lines:
        if line.startswith(" ") and unfolded:
            unfolded[-1] = unfolded[-1] + line[1:]
        else:
            unfolded.append(line)

    attrs = {}
    for line in unfolded:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue

        if "::" in raw:
            key, value = raw.split("::", 1)
            key = key.strip()
            value = value.strip()
            try:
                decoded = base64.b64decode(value)
            except Exception:
                decoded = b""
            attrs.setdefault(key, []).append(decoded)
            continue

        if ":" in raw:
            key, value = raw.split(":", 1)
            attrs.setdefault(key.strip(), []).append(value.strip())

    return attrs


def _lookup_ad_group_ldapsearch(group_name, auth_context):
    ldapsearch_bin = _resolve_ldapsearch_executable()
    if not ldapsearch_bin:
        return None, "ldapsearch executable was not found on this server"

    config, config_error = _resolve_ldap_config()
    if config_error:
        return None, config_error

    password = str((auth_context or {}).get("password") or "")
    if not password:
        return None, "LDAP bind requires username and password"

    bind_user = _resolve_ldapsearch_bind_user(auth_context, config)
    if not bind_user:
        return None, "LDAP bind requires username"

    primary_scheme = "ldaps" if bool(config.get("use_ssl")) else "ldap"
    primary_port = int(config.get("port") or (636 if primary_scheme == "ldaps" else 389))
    uri_candidates = [f"{primary_scheme}://{config.get('server')}:{primary_port}"]

    # Read-only fallback matrix for environments where LDAPS 636 is blocked or cert chain is internal.
    if primary_scheme == "ldaps":
        uri_candidates.append(f"ldap://{config.get('server')}:389")
    else:
        uri_candidates.append(f"ldaps://{config.get('server')}:636")
    escaped = _escape_ldap_filter_value(group_name)
    search_filter = (
        f"(&(objectClass=group)(|"
        f"(cn={escaped})"
        f"(name={escaped})"
        f"(sAMAccountName={escaped})"
        "))"
    )

    last_error = ""
    completed = None
    for uri in uri_candidates:
        cmd = [
            ldapsearch_bin,
            "-LLL",
            "-x",
            "-o",
            "nettimeout=8",
            "-o",
            "TLS_REQCERT=never",
            "-H",
            uri,
            "-D",
            bind_user,
            "-w",
            password,
            "-b",
            str(config.get("base_dn") or ""),
            search_filter,
            "cn",
            "name",
            "sAMAccountName",
            "distinguishedName",
            "objectGUID",
            "objectSid",
            "groupType",
        ]

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except Exception as exc:
            last_error = f"ldapsearch execution failed: {exc}"
            continue

        if completed.returncode == 0:
            break

        error_text = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        last_error = f"{uri}: {error_text or f'ldapsearch failed with exit code {completed.returncode}'}"
        completed = None

    if completed is None:
        return None, last_error or "ldapsearch failed"

    attrs = _parse_ldif_attributes(completed.stdout or "")
    if not attrs:
        return {"found": False}, ""

    dn = ""
    if attrs.get("distinguishedName"):
        dn = _guid_to_string(attrs.get("distinguishedName", [""])[0])
    elif attrs.get("dn"):
        dn = _guid_to_string(attrs.get("dn", [""])[0])

    name = ""
    if attrs.get("name"):
        name = _guid_to_string(attrs.get("name", [""])[0])
    elif attrs.get("cn"):
        name = _guid_to_string(attrs.get("cn", [""])[0])

    sam = _guid_to_string((attrs.get("sAMAccountName") or [""])[0])
    guid = _guid_to_string((attrs.get("objectGUID") or [None])[0])
    sid = _sid_to_string((attrs.get("objectSid") or [None])[0])
    group_type_raw = (attrs.get("groupType") or [""])[0]
    try:
        group_type = int(str(group_type_raw).strip())
    except Exception:
        group_type = None

    return {
        "found": bool(dn or name or sam),
        "name": name,
        "samAccountName": sam,
        "distinguishedName": dn,
        "objectGUID": guid,
        "sid": sid,
        "groupCategory": _group_category_from_group_type(group_type) if group_type is not None else "",
        "groupScope": _group_scope_from_group_type(group_type) if group_type is not None else "",
    }, ""
import json
import re
import shutil
import subprocess


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
    if error:
        return None, error
    if not isinstance(data, dict):
        return None, "AD lookup returned an invalid response"
    return data, ""


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
        return False, f"AD update failed for {sam}: {update_error}"

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
        return False, f"AD clear failed for {sam}: {clear_error}"

    return True, f"Cleared AD phone fields for {sam}"
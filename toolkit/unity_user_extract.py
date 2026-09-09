import os

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_USERS = 5000


def _unity_url(unity_server, path):
    base = str(unity_server or "").strip()
    if not base.startswith("http://") and not base.startswith("https://"):
        base = f"https://{base}"
    return f"{base.rstrip('/')}/{str(path or '').lstrip('/')}"


def _as_text(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value).strip()


def _first_value(record, names):
    for name in names:
        value = record.get(name)
        if value is not None and _as_text(value):
            return value
    return ""


def _unified_messaging_value(record):
    candidates = (
        "UnifiedMessaging",
        "UnifiedMessagingEnabled",
        "IsUnifiedMessagingEnabled",
        "HasUnifiedMessaging",
        "UnifiedMessagingAccount",
    )
    for name in candidates:
        if name not in record:
            continue
        value = record.get(name)
        if isinstance(value, bool):
            return "Yes" if value else "No"
        text = _as_text(value).lower()
        if text in {"true", "yes", "enabled", "active", "1"}:
            return "Yes"
        if text in {"false", "no", "disabled", "inactive", "0", "none", "null"}:
            return "No"
        return _as_text(value)
    return "Unknown"


def _extract_user_list(payload):
    if not isinstance(payload, dict):
        return []
    users = payload.get("User")
    if isinstance(users, dict):
        return [users]
    if isinstance(users, list):
        return [item for item in users if isinstance(item, dict)]
    users = payload.get("users")
    if isinstance(users, dict):
        return [users]
    if isinstance(users, list):
        return [item for item in users if isinstance(item, dict)]
    return []


def extract_unity_users(unity_server, unity_user, unity_pass, max_users=MAX_USERS):
    clean_server = str(unity_server or "").strip()
    if not clean_server:
        raise ValueError("Unity server is required")
    if not str(unity_user or "").strip() or not unity_pass:
        raise ValueError("Unity credentials are required")
    safe_max_users = max(1, min(int(max_users or MAX_USERS), MAX_USERS))
    response = requests.get(
        _unity_url(clean_server, "/vmrest/users"),
        params={"limit": safe_max_users},
        auth=HTTPBasicAuth(str(unity_user).strip(), unity_pass),
        headers={"Accept": "application/json"},
        verify=False,
        timeout=120,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Unity user extract failed with HTTP {response.status_code}: {(response.text or '')[:500]}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("Unity user extract returned invalid JSON") from exc

    rows = []
    for user in _extract_user_list(payload)[:safe_max_users]:
        rows.append({
            "alias": _first_value(user, ("Alias", "alias")),
            "first_name": _first_value(user, ("FirstName", "firstName", "Firstname")),
            "last_name": _first_value(user, ("LastName", "lastName", "Lastname")),
            "email": _first_value(user, ("EmailAddress", "emailAddress", "Email", "email")),
            "extension": _first_value(user, ("DtmfAccessId", "dtmfAccessId", "Extension", "extension")),
            "unified_messaging": _unified_messaging_value(user),
        })
    rows.sort(key=lambda row: (row["last_name"].lower(), row["first_name"].lower(), row["extension"]))
    return rows

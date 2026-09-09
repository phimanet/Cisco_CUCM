import os
import time

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_USERS = 100000
ROWS_PER_PAGE = 2000


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
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    if any(key in payload for key in ("Alias", "alias", "FirstName", "firstName", "DtmfAccessId", "dtmfAccessId")):
        return [payload]
    for key, value in payload.items():
        if str(key).lower() in {"user", "users", "userlist", "userlistitems"}:
            found = _extract_user_list(value)
            if found:
                return found
    for value in payload.values():
        if isinstance(value, (dict, list)):
            found = _extract_user_list(value)
            if found:
                return found
    return []


def extract_unity_users(unity_server, unity_user, unity_pass, max_users=MAX_USERS, progress_callback=None):
    clean_server = str(unity_server or "").strip()
    if not clean_server:
        raise ValueError("Unity server is required")
    if not str(unity_user or "").strip() or not unity_pass:
        raise ValueError("Unity credentials are required")
    safe_max_users = max(1, min(int(max_users or MAX_USERS), MAX_USERS))
    rows = []
    page_number = 0
    first_page_retry_done = False
    while len(rows) < safe_max_users:
        response = requests.get(
            _unity_url(clean_server, "/vmrest/users"),
            params={"rowsperpage": min(ROWS_PER_PAGE, safe_max_users - len(rows)), "pageNumber": page_number},
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
        page_users = _extract_user_list(payload)
        if not page_users and page_number == 0 and not first_page_retry_done:
            first_page_retry_done = True
            page_number = 1
            continue
        if not page_users and page_number == 1 and first_page_retry_done and not rows:
            if isinstance(payload, dict):
                shape = ", ".join(sorted(str(key) for key in payload.keys())[:20]) or "no top-level keys"
            else:
                shape = type(payload).__name__
            raise RuntimeError(f"Unity returned no user records. Response shape: {shape}")
        for user in page_users:
            rows.append({
                "alias": _first_value(user, ("Alias", "alias")),
                "first_name": _first_value(user, ("FirstName", "firstName", "Firstname")),
                "last_name": _first_value(user, ("LastName", "lastName", "Lastname")),
                "email": _first_value(user, ("EmailAddress", "emailAddress", "Email", "email")),
                "extension": _first_value(user, ("DtmfAccessId", "dtmfAccessId", "Extension", "extension")),
                "unified_messaging": _unified_messaging_value(user),
            })
        if progress_callback:
            progress_callback(len(rows), page_number + 1)
        if len(page_users) < min(ROWS_PER_PAGE, safe_max_users - len(rows) + len(page_users)):
            break
        page_number += 1
        time.sleep(0.05)
    rows.sort(key=lambda row: (row["last_name"].lower(), row["first_name"].lower(), row["extension"]))
    return rows

import os
import re
import time
from urllib.parse import quote_plus

import requests
import urllib3
from requests.auth import HTTPBasicAuth

from toolkit import unity_number_search as number_settings

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
        "UnifiedMessagingAccounts",
    )
    for name in candidates:
        if name not in record:
            continue
        value = record.get(name)
        if isinstance(value, dict):
            value = _first_value(value, ("Name", "name", "DisplayName", "displayName", "ServiceName", "serviceName")) or value
        elif isinstance(value, list):
            names = []
            for item in value:
                if isinstance(item, dict):
                    item_name = _first_value(item, ("Name", "name", "DisplayName", "displayName", "ServiceName", "serviceName"))
                    if item_name:
                        names.append(item_name)
                elif _as_text(item):
                    names.append(_as_text(item))
            value = ", ".join(names) if names else value
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


def _extract_um_account_list(payload):
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key, value in payload.items():
        if str(key).lower() in {"unifiedmessagingaccount", "unifiedmessagingaccounts", "account", "accounts"}:
            found = _extract_um_account_list(value)
            if found:
                return found
    for value in payload.values():
        if isinstance(value, (dict, list)):
            found = _extract_um_account_list(value)
            if found:
                return found
    return []


def _um_service_name(account):
    return _first_value(account, ("ServiceName", "serviceName", "UnifiedMessagingService", "unifiedMessagingService", "UMService", "umService", "Service", "service", "Name", "name"))


def _um_account_alias(account):
    return _first_value(account, ("Alias", "alias", "UserAlias", "userAlias"))


def _um_account_user_id(account):
    return _first_value(account, ("UserObjectId", "userObjectId", "UserObjectID", "userObjectID", "ObjectId", "objectId", "UserId", "userId"))


def _load_um_service_map(unity_server, unity_user, unity_pass):
    service_map = {}
    for path in ("/vmrest/unifiedMessagingAccounts", "/vmrest/unifiedmessagingaccounts"):
        try:
            response = requests.get(
                _unity_url(unity_server, path),
                params={"rowsPerPage": ROWS_PER_PAGE, "pageNumber": 0},
                auth=HTTPBasicAuth(str(unity_user).strip(), unity_pass),
                headers={"Accept": "application/json"},
                verify=False,
                timeout=120,
            )
        except requests.RequestException:
            continue
        if response.status_code == 404:
            continue
        if response.status_code != 200:
            raise RuntimeError(f"Unity Unified Messaging Accounts lookup failed with HTTP {response.status_code}: {(response.text or '')[:500]}")
        try:
            accounts = _extract_um_account_list(response.json())
        except ValueError as exc:
            raise RuntimeError("Unity Unified Messaging Accounts returned invalid JSON") from exc
        for account in accounts:
            service = _um_service_name(account)
            alias = _um_account_alias(account)
            user_id = _um_account_user_id(account)
            if alias and service:
                service_map[alias.lower()] = service
            if user_id and service:
                service_map[f"id:{user_id.lower()}"] = service
        return service_map
    return service_map


def extract_unity_users(unity_server, unity_user, unity_pass, max_users=MAX_USERS, progress_callback=None):
    clean_server = str(unity_server or "").strip()
    if not clean_server:
        raise ValueError("Unity server is required")
    if not str(unity_user or "").strip() or not unity_pass:
        raise ValueError("Unity credentials are required")
    safe_max_users = max(1, min(int(max_users or MAX_USERS), MAX_USERS))
    service_map = _load_um_service_map(clean_server, unity_user, unity_pass)
    rows = []
    page_number = 0
    first_page_retry_done = False
    while len(rows) < safe_max_users:
        response = requests.get(
            _unity_url(clean_server, "/vmrest/users"),
            params={"rowsPerPage": min(ROWS_PER_PAGE, safe_max_users - len(rows)), "pageNumber": page_number},
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
            alias = _first_value(user, ("Alias", "alias"))
            object_id = _first_value(user, ("ObjectId", "objectId", "ObjectID", "objectID"))
            rows.append({
                "alias": alias,
                "first_name": _first_value(user, ("FirstName", "firstName", "Firstname")),
                "last_name": _first_value(user, ("LastName", "lastName", "Lastname")),
                "email": _first_value(user, ("EmailAddress", "emailAddress", "Email", "email")),
                "extension": _first_value(user, ("DtmfAccessId", "dtmfAccessId", "Extension", "extension")),
                "unified_messaging": service_map.get(f"id:{object_id.lower()}", service_map.get(alias.lower(), _unified_messaging_value(user))) if object_id or alias else _unified_messaging_value(user),
            })
        if progress_callback:
            progress_callback(len(rows), page_number + 1)
        if len(page_users) < min(ROWS_PER_PAGE, safe_max_users - len(rows) + len(page_users)):
            break
        page_number += 1
        time.sleep(0.05)
    rows.sort(key=lambda row: (row["last_name"].lower(), row["first_name"].lower(), row["extension"]))
    return rows


def _person_identity(record):
    identity = _as_text(_first_value(record, ("ObjectId", "ObjectID", "objectId")))
    if not identity or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", identity):
        raise number_settings.UnitySearchError("Unity did not return a valid user ObjectId.")
    return {"object_id": identity, "name": _as_text(record.get("DisplayName")) or " ".join(_as_text(record.get(key)) for key in ("FirstName", "LastName")).strip() or _as_text(record.get("Alias")),
            "alias": _as_text(record.get("Alias")), "first_name": _as_text(record.get("FirstName")), "last_name": _as_text(record.get("LastName")),
            "email": _as_text(record.get("EmailAddress") or record.get("SmtpAddress")), "smtp_address": _as_text(record.get("SmtpAddress")),
            "extension": _as_text(record.get("DtmfAccessId") or record.get("Extension"))}


def _read_user_resource(client, host, username, password, resource, params=None):
    response = client.get("https://" + host + resource, params=params, auth=(username, password),
                          headers={"Accept": "application/json"}, verify=False, timeout=(5, 15), allow_redirects=False)
    if response.status_code != 200:
        raise number_settings.UnitySearchError(f"Unity user read failed HTTP {response.status_code}; this does not establish that the user is absent.")
    try:
        return response.json()
    except ValueError:
        raise number_settings.UnitySearchError("Unity user read returned invalid JSON.") from None


def find_unity_person(host, username, password, search_by, value):
    host = number_settings.normalize_host(host)
    value = str(value or "").strip()
    first_name = ""
    if search_by == "extension":
        value = number_settings.normalize_query(value)
        filters = [("DtmfAccessId", "is", value)]
    elif search_by == "email":
        if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value) or len(value) > 254:
            raise ValueError("Enter a valid email address.")
        filters = [("EmailAddress", "is", value), ("SmtpAddress", "is", value)]
    elif search_by == "name":
        if not re.fullmatch(r"[\w .'-]{2,100}", value):
            raise ValueError("Enter a last name or First Last name, without query operators.")
        parts = value.split()
        first_name = parts[0] if len(parts) > 1 else ""
        filters = [("LastName", "startswith", " ".join(parts[1:]) if first_name else value)]
    else:
        raise ValueError("Choose Name, Email, or Extension.")
    people = {}
    requests_count = 0
    warnings = []
    with requests.Session() as client:
        for field, operator, term in filters:
            resource = "/vmrest/users?query=" + quote_plus(f"({field} {operator} {term})", safe="()")
            consumed = 0
            previous = set()
            count_only_retry = False
            for page in range(10):
                requests_count += 1
                payload = _read_user_resource(client, host, username, password, resource, {"rowsPerPage": 50, "pageNumber": page})
                try:
                    records, total = number_settings._records(payload)
                except number_settings.UnityCountOnlyPage:
                    if page == 0:
                        count_only_retry = True
                        continue
                    raise
                if count_only_retry and consumed == 0 and not records:
                    raise number_settings.UnitySearchError("Unity page 1 returned no users after a positive count-only response.")
                if page == 1 and consumed == 0 and not records and total:
                    raise number_settings.UnitySearchError("Unity returned a positive user count without page-1 records.")
                for record in records:
                    person = _person_identity(record)
                    if person["object_id"] in previous:
                        raise number_settings.UnitySearchError("Unity user lookup repeated records across pages; narrow the search.")
                    previous.add(person["object_id"])
                    if search_by == "email" and value.casefold() not in {person["email"].casefold(), person["smtp_address"].casefold()}:
                        continue
                    if search_by == "extension" and person["extension"] != value:
                        continue
                    if first_name and not person["first_name"].casefold().startswith(first_name.casefold()):
                        continue
                    people[person["object_id"]] = person
                    if len(people) > 10:
                        raise ValueError("More than ten users match; use a more specific name, email, or primary extension.")
                consumed += len(records)
                if not records and total and consumed < total:
                    raise number_settings.UnitySearchError("Unity user lookup returned an unexpectedly empty page.")
                if total is not None and consumed >= total or total is None and len(records) < 50:
                    break
            else:
                raise ValueError("User lookup page limit reached; narrow the search.")
    return {"host": host, "search_by": search_by, "query": value, "users": sorted(people.values(), key=lambda person: (person["name"].casefold(), person["alias"])),
            "requests": requests_count, "warnings": warnings, "checked_at": number_settings.timestamp()}


def start_person_number_extract(host, username, password, object_id):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", str(object_id or "")):
        raise ValueError("Choose a valid Unity user.")
    host = number_settings.normalize_host(host)
    resource = "/vmrest/users/" + object_id
    with requests.Session() as client:
        payload = _read_user_resource(client, host, username, password, resource)
    records, _ = number_settings._records(payload)
    if len(records) != 1 or _person_identity(records[0])["object_id"] != object_id:
        raise number_settings.UnitySearchError("Unity returned a different user identity; extraction stopped.")
    record = records[0]
    state = number_settings.new_cache_scan(host)
    state.update(purpose="mailbox_number_extract", person=_person_identity(record), requests=1, records=1,
                 mailbox_resources=[resource], tasks=[], scheduled=[resource],
                 coverage=[{"resource": resource, "status": "Checked", "detail": "Selected user profile read and identity verified."}])
    handler = record.get("CallHandlerURI") or record.get("PrimaryCallHandlerURI")
    handler_id = record.get("CallHandlerObjectId") or record.get("PrimaryCallHandlerObjectId")
    if not handler and handler_id:
        handler = "/vmrest/handlers/callhandlers/" + str(handler_id)
    if handler:
        handler = number_settings.safe_resource(handler, host)
        if not re.fullmatch(r"/vmrest/handlers/callhandlers/[A-Za-z0-9_.-]+", handler):
            raise number_settings.UnitySearchError("Unity primary handler link is invalid; extraction stopped.")
        state["mailbox_resources"].append(handler)
    else:
        state["coverage"].append({"resource": resource, "status": "Failed", "detail": "Primary call handler link was not returned; transfer/greeting/caller-input fields were not searched."})
    owner = {"id": object_id, "name": state["person"]["name"], "type": "User Mailbox"}
    number_settings._ingest(state, record, {"resource": resource, "label": "User Mailbox", "page": 0, "owner": owner})
    for child in ("alternateextensions", "usernotificationdevices", "messagewaitingindicators"):
        number_settings._schedule(state, resource + "/" + child, "User Mailbox", owner)
    if handler:
        handler_owner = {"id": handler.rsplit("/", 1)[-1], "name": state["person"]["name"] + " (primary handler)", "type": "Primary User Call Handler"}
        for child in ("", "/transferoptions", "/menuentries", "/greetings"):
            number_settings._schedule(state, handler + child, "Primary User Call Handler", handler_owner)
    state["scope"] = "Selected user mailbox number-entry fields"
    return state


def person_number_report(state):
    rows = []
    seen = set()
    for item in state["fields"]:
        key = (item["resource"], item["field"], item["value"])
        if key not in seen:
            seen.add(key)
            rows.append(item)
    gaps = [item for item in state["coverage"] if item["status"] != "Checked"]
    return {"schema_version": 1, "host": state["host"], "job_id": state["job_id"], "status": state["status"], "person": state["person"],
            "rows": sorted(rows, key=lambda item: (item["resource"], item["field"])), "field_count": len(rows), "references": state["edges"],
            "requests": state["requests"], "records": state["records"], "pending_resources": len(state["tasks"]), "coverage": state["coverage"],
            "complete": state["status"] == "completed" and not gaps, "coverage_gaps": gaps, "checked_at": state["updated_at"],
            "failures": gaps, "excluded_links": state["excluded_links"],
            "scope": "Selected user mailbox number-entry fields", "retention": "Latest selected-user scan and latest completed extract per Unity host only; not an archive. Stored outside Git; normal restarts/pulls preserve data, not deletion or older data/VM restores.",
            "limitations": "Read-only selected-user extract, not a global number-reference search or deletion clearance. Primary extension lookup does not search every user's transfer destination. Recorded audio/messages, credentials and other users/handlers are excluded. Caller-input/greeting references are stored links, not verified active call paths. Coverage gaps are not empty settings."}

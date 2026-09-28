"""Read-only Microsoft Graph helpers for Teams Calling Plan visibility.

Auth: Entra app registration using client credentials. Required application permissions:
User.Read.All, Organization.Read.All (subscribedSkus), TeamsTelephoneNumber.Read.All.
"""
import os
import re
import threading
import time
from urllib.parse import quote

import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_TIMEOUT_SECONDS = int((os.getenv("MS_GRAPH_TIMEOUT_SECONDS", "25") or "25").strip())
GRAPH_MAX_PAGES = int((os.getenv("MS_GRAPH_MAX_PAGES", "50") or "50").strip())

_TOKEN_CACHE = {"token": "", "expires_at": 0.0}
_TOKEN_LOCK = threading.Lock()

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TENANT_RE = re.compile(r"^[A-Za-z0-9.-]+$")

USER_SELECT = ",".join([
    "id", "displayName", "givenName", "surname", "userPrincipalName", "mail", "jobTitle",
    "department", "officeLocation", "usageLocation", "accountEnabled", "businessPhones",
    "mobilePhone", "employeeId",
])


class GraphError(RuntimeError):
    def __init__(self, message, status_code=0):
        super().__init__(message)
        self.status_code = status_code


def _config():
    return (
        (os.getenv("MS_GRAPH_TENANT_ID", "") or "").strip(),
        (os.getenv("MS_GRAPH_CLIENT_ID", "") or "").strip(),
        (os.getenv("MS_GRAPH_CLIENT_SECRET", "") or "").strip(),
    )


def _csv_env(name, default):
    return [p.strip().upper() for p in (os.getenv(name, default) or default).split(",") if p.strip()]


def is_calling_plan_name(name):
    upper = str(name or "").strip().upper()
    if not upper or upper in _csv_env("MS_CALLING_PLAN_EXCLUDE", "MCOPSTNC"):
        return False
    return any(upper.startswith(prefix) for prefix in _csv_env("MS_CALLING_PLAN_PREFIXES", "MCOPSTN"))


def is_teams_phone_name(name):
    upper = str(name or "").strip().upper()
    return any(upper.startswith(prefix) for prefix in _csv_env("MS_TEAMS_PHONE_PREFIXES", "MCOEV"))


def integration_status():
    tenant_id, client_id, client_secret = _config()
    return {
        "configured": bool(tenant_id and client_id and client_secret),
        "tenant_id_set": bool(tenant_id),
        "client_id_set": bool(client_id),
        "client_secret_set": bool(client_secret),
        "calling_plan_prefixes": _csv_env("MS_CALLING_PLAN_PREFIXES", "MCOPSTN"),
        "calling_plan_excluded": _csv_env("MS_CALLING_PLAN_EXCLUDE", "MCOPSTNC"),
    }


def _get_token():
    tenant_id, client_id, client_secret = _config()
    if not (tenant_id and client_id and client_secret):
        raise GraphError("Microsoft Graph is not configured. Set MS_GRAPH_TENANT_ID, MS_GRAPH_CLIENT_ID, and MS_GRAPH_CLIENT_SECRET in .env.")
    if not _TENANT_RE.match(tenant_id):
        raise GraphError("MS_GRAPH_TENANT_ID has an invalid format.")
    with _TOKEN_LOCK:
        if _TOKEN_CACHE["token"] and time.time() < _TOKEN_CACHE["expires_at"] - 120:
            return _TOKEN_CACHE["token"]
        response = requests.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=GRAPH_TIMEOUT_SECONDS,
        )
        payload = _safe_json(response)
        if response.status_code != 200 or not payload.get("access_token"):
            detail = payload.get("error_description") or payload.get("error") or response.text[:300]
            raise GraphError(f"Microsoft Graph token request failed (HTTP {response.status_code}): {str(detail).splitlines()[0]}", response.status_code)
        _TOKEN_CACHE["token"] = payload["access_token"]
        _TOKEN_CACHE["expires_at"] = time.time() + int(payload.get("expires_in", 3600) or 3600)
        return _TOKEN_CACHE["token"]


def _safe_json(response):
    try:
        data = response.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def _graph_get(url, params=None, extra_headers=None):
    if not url.startswith(GRAPH_BASE):
        url = GRAPH_BASE + url
    headers = {"Authorization": f"Bearer {_get_token()}", "Accept": "application/json"}
    headers.update(extra_headers or {})
    for attempt in range(3):
        response = requests.get(url, params=params, headers=headers, timeout=GRAPH_TIMEOUT_SECONDS)
        if response.status_code in (429, 503, 504) and attempt < 2:
            time.sleep(min(10, int(response.headers.get("Retry-After", "2") or "2")))
            continue
        break
    payload = _safe_json(response)
    if response.status_code != 200:
        error = payload.get("error", {}) if isinstance(payload.get("error"), dict) else {}
        message = error.get("message") or response.text[:300]
        raise GraphError(f"Graph GET failed (HTTP {response.status_code}): {message}", response.status_code)
    return payload


def _graph_get_all(url, params=None, extra_headers=None):
    items = []
    payload = _graph_get(url, params=params, extra_headers=extra_headers)
    items.extend(payload.get("value", []) or [])
    pages = 1
    next_link = payload.get("@odata.nextLink", "")
    while next_link and pages < GRAPH_MAX_PAGES:
        payload = _graph_get(next_link, extra_headers=extra_headers)
        items.extend(payload.get("value", []) or [])
        next_link = payload.get("@odata.nextLink", "")
        pages += 1
    return items


def _odata_quote(value):
    return str(value or "").replace("'", "''")


def _list_number_assignments(filter_expr):
    """numberAssignments pages with $top/$skip (max 1000 per page)."""
    results = []
    skip = 0
    for _ in range(GRAPH_MAX_PAGES):
        payload = _graph_get(
            "/admin/teams/telephoneNumberManagement/numberAssignments",
            params={"$filter": filter_expr, "$top": "1000", "$skip": str(skip)},
        )
        page = payload.get("value", []) or []
        results.extend(page)
        if len(page) < 1000:
            break
        skip += 1000
    return results


def _number_row(item):
    return {
        "telephone_number": item.get("telephoneNumber", ""),
        "number_type": item.get("numberType", ""),
        "assignment_status": item.get("assignmentStatus", ""),
        "activation_state": item.get("activationState", ""),
        "assignment_category": item.get("assignmentCategory", ""),
        "capabilities": item.get("capabilities", []) or [],
        "city": item.get("city", "") or "",
        "iso_country_code": item.get("isoCountryCode", "") or "",
        "assignment_target_id": item.get("assignmentTargetId", "") or "",
    }


def lookup_person(identifier):
    clean = str(identifier or "").strip()
    if not _EMAIL_RE.match(clean):
        raise GraphError("Enter a valid email address or user principal name (name@domain).")

    warnings = []
    user = None
    try:
        user = _graph_get(f"/users/{quote(clean, safe='@')}", params={"$select": USER_SELECT})
    except GraphError as exc:
        if exc.status_code != 404:
            raise
    if not user:
        matches = _graph_get(
            "/users",
            params={"$filter": f"mail eq '{_odata_quote(clean)}' or proxyAddresses/any(p:p eq 'smtp:{_odata_quote(clean)}')", "$select": USER_SELECT, "$count": "true"},
            extra_headers={"ConsistencyLevel": "eventual"},
        ).get("value", []) or []
        if not matches:
            return {"found": False, "identifier": clean}
        user = matches[0]
        if len(matches) > 1:
            warnings.append(f"{len(matches)} users matched this email; showing the first match.")

    user_id = str(user.get("id", "") or "")
    if not _GUID_RE.match(user_id):
        raise GraphError("Graph returned an unexpected user ID format.")

    licenses = []
    for detail in _graph_get_all(f"/users/{user_id}/licenseDetails"):
        plans = [
            {"name": plan.get("servicePlanName", ""), "status": plan.get("provisioningStatus", "")}
            for plan in (detail.get("servicePlans", []) or [])
        ]
        sku_part = detail.get("skuPartNumber", "")
        licenses.append({
            "sku_part_number": sku_part,
            "sku_id": detail.get("skuId", ""),
            "calling_plan": is_calling_plan_name(sku_part) or any(is_calling_plan_name(p["name"]) and p["status"] != "Disabled" for p in plans),
            "teams_phone": is_teams_phone_name(sku_part) or any(is_teams_phone_name(p["name"]) and p["status"] != "Disabled" for p in plans),
            "voice_plans": [p for p in plans if is_calling_plan_name(p["name"]) or is_teams_phone_name(p["name"])],
        })

    numbers = []
    try:
        numbers = [_number_row(item) for item in _list_number_assignments(f"assignmentTargetId eq '{user_id}'")]
    except GraphError as exc:
        warnings.append(f"Teams phone number lookup unavailable: {exc}")

    return {
        "found": True,
        "identifier": clean,
        "user": {
            "id": user_id,
            "display_name": user.get("displayName", ""),
            "given_name": user.get("givenName", ""),
            "surname": user.get("surname", ""),
            "user_principal_name": user.get("userPrincipalName", ""),
            "mail": user.get("mail", ""),
            "job_title": user.get("jobTitle", ""),
            "department": user.get("department", ""),
            "office_location": user.get("officeLocation", ""),
            "usage_location": user.get("usageLocation", ""),
            "account_enabled": user.get("accountEnabled"),
            "business_phones": user.get("businessPhones", []) or [],
            "mobile_phone": user.get("mobilePhone", "") or "",
            "employee_id": user.get("employeeId", "") or "",
        },
        "licenses": licenses,
        "has_calling_plan": any(item["calling_plan"] for item in licenses),
        "has_teams_phone": any(item["teams_phone"] for item in licenses),
        "phone_numbers": numbers,
        "warnings": warnings,
    }


def list_calling_plan_holders():
    warnings = []
    skus = []
    for sku in _graph_get_all("/subscribedSkus"):
        part = sku.get("skuPartNumber", "")
        plan_names = [p.get("servicePlanName", "") for p in (sku.get("servicePlans", []) or [])]
        if is_calling_plan_name(part) or any(is_calling_plan_name(name) for name in plan_names):
            enabled = int(((sku.get("prepaidUnits") or {}).get("enabled", 0)) or 0)
            consumed = int(sku.get("consumedUnits", 0) or 0)
            skus.append({"sku_id": sku.get("skuId", ""), "sku_part_number": part, "enabled": enabled, "consumed": consumed, "available": max(0, enabled - consumed)})

    holders = {}
    for sku in skus:
        if not _GUID_RE.match(str(sku["sku_id"] or "")):
            continue
        users = _graph_get_all(
            "/users",
            params={
                "$filter": f"assignedLicenses/any(x:x/skuId eq {sku['sku_id']})",
                "$select": "id,displayName,userPrincipalName,mail,department,accountEnabled,usageLocation",
                "$count": "true",
                "$top": "999",
            },
            extra_headers={"ConsistencyLevel": "eventual"},
        )
        for user in users:
            entry = holders.setdefault(user.get("id", ""), {
                "id": user.get("id", ""),
                "display_name": user.get("displayName", ""),
                "user_principal_name": user.get("userPrincipalName", ""),
                "mail": user.get("mail", "") or "",
                "department": user.get("department", "") or "",
                "account_enabled": user.get("accountEnabled"),
                "usage_location": user.get("usageLocation", "") or "",
                "skus": [],
                "phone_numbers": [],
            })
            if sku["sku_part_number"] not in entry["skus"]:
                entry["skus"].append(sku["sku_part_number"])

    unassigned_calling_plan_numbers = 0
    try:
        for item in _list_number_assignments("numberType eq 'callingPlan'"):
            target = item.get("assignmentTargetId", "") or ""
            if item.get("assignmentStatus") == "unassigned":
                unassigned_calling_plan_numbers += 1
            if target in holders:
                holders[target]["phone_numbers"].append(item.get("telephoneNumber", ""))
    except GraphError as exc:
        unassigned_calling_plan_numbers = None
        warnings.append(f"Teams phone number inventory unavailable: {exc}")

    rows = sorted(holders.values(), key=lambda r: (str(r["display_name"]).lower(), r["user_principal_name"]))
    return {
        "skus": skus,
        "holders": rows,
        "holder_count": len(rows),
        "unassigned_calling_plan_numbers": unassigned_calling_plan_numbers,
        "warnings": warnings,
    }

import datetime
import hashlib
import json
import os
import re
import tempfile
from urllib.parse import parse_qs, quote, urljoin, urlsplit

import requests


API_BASE = "https://webexapis.com/v1/"
WEBEX_LDAP_GROUP = "SSO_WebEX_AMNHealthcare"


class WebexError(RuntimeError):
    pass


def configuration_status():
    return {"configured": bool(os.getenv("WEBEX_ACCESS_TOKEN", "").strip() and os.getenv("WEBEX_ORG_ID", "").strip()),
            "token_configured": bool(os.getenv("WEBEX_ACCESS_TOKEN", "").strip()),
            "org_configured": bool(os.getenv("WEBEX_ORG_ID", "").strip()), "read_only": True}


def _get(session, url, params=None):
    try:
        response = session.get(url, params=params, timeout=20, allow_redirects=False)
    except requests.RequestException as exc:
        raise WebexError("Cisco Webex request failed (network/TLS error).") from exc
    if response.status_code != 200:
        if response.status_code == 401:
            raise WebexError("Cisco Webex token is invalid or expired.")
        if response.status_code == 403:
            raise WebexError("Cisco Webex read access was denied; verify administrator permissions and people/license read scopes.")
        if response.status_code == 429:
            raise WebexError("Cisco Webex is throttling requests; retry later.")
        raise WebexError(f"Cisco Webex read failed (HTTP {response.status_code}).")
    try:
        payload = response.json()
    except ValueError as exc:
        raise WebexError("Cisco Webex returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise WebexError("Cisco Webex returned an invalid response.")
    return payload, response.links.get("next", {}).get("url", "")


def _list(session, resource, org_id, extra=None):
    params = {"orgId": org_id, **(extra or {})}
    url = API_BASE + resource
    rows = []
    seen = set()
    for _ in range(100):
        if url in seen:
            raise WebexError("Cisco Webex pagination repeated a page.")
        seen.add(url)
        payload, next_link = _get(session, url, params)
        items = payload.get("items")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise WebexError("Cisco Webex returned incomplete list data.")
        rows.extend(items)
        if not next_link:
            return rows
        url = urljoin(url, next_link)
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        if parsed.scheme != "https" or parsed.netloc != "webexapis.com" or parsed.path != "/v1/" + resource or parsed.fragment or query.get("orgId") != [org_id]:
            raise WebexError("Cisco Webex returned an unsafe or different-organization page link.")
        if extra and any(query.get(key) != [str(value)] for key, value in extra.items() if key != "max"):
            raise WebexError("Cisco Webex pagination changed the lookup filter.")
        params = None
    raise WebexError("Cisco Webex page limit exceeded; lookup is incomplete.")


def lookup_licenses(email):
    email = str(email or "").strip()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("Enter a valid employee email address.")
    token = os.getenv("WEBEX_ACCESS_TOKEN", "").strip()
    org_id = os.getenv("WEBEX_ORG_ID", "").strip()
    if not token or not org_id:
        raise WebexError("Cisco Webex is not configured. Set WEBEX_ACCESS_TOKEN and WEBEX_ORG_ID on the server.")
    with requests.Session() as session:
        session.headers.update({"Authorization": "Bearer " + token, "Accept": "application/json"})
        candidates = _list(session, "people", org_id, {"email": email, "max": 2})
        people = {}
        for person in candidates:
            if person.get("orgId") != org_id or not isinstance(person.get("emails"), list) or not person.get("id"):
                raise WebexError("Cisco Webex returned an invalid or different-organization person.")
            if email.casefold() in {str(value).casefold() for value in person["emails"]}:
                people[person["id"]] = person
        if not people:
            raise WebexError("Person not found in the configured Cisco Webex organization; previous saved lookup is retained.")
        if len(people) != 1:
            raise WebexError("More than one Cisco Webex person matched this email; lookup requires a unique identity.")
        person_id = next(iter(people))
        person, _ = _get(session, API_BASE + "people/" + quote(person_id, safe=""))
        if person.get("id") != person_id or person.get("orgId") != org_id or not isinstance(person.get("emails"), list) or email.casefold() not in {str(value).casefold() for value in person["emails"]}:
            raise WebexError("Cisco Webex person identity changed or did not match the requested organization/email.")
        assigned = person.get("licenses")
        if not isinstance(assigned, list) or any(not isinstance(value, str) or not value for value in assigned):
            raise WebexError("Assigned licenses were not returned; this does not mean the user has no licenses.")
        catalog = _list(session, "licenses", org_id) if assigned else []
        names = {}
        for item in catalog:
            if not item.get("id") or not item.get("name") or (item.get("orgId") and item["orgId"] != org_id):
                raise WebexError("Cisco Webex license catalog is incomplete or belongs to a different organization.")
            names[item["id"]] = item
        licenses = [{"id": license_id, "name": str(names.get(license_id, {}).get("name", "Name unavailable")),
                     "site_url": str(names.get(license_id, {}).get("siteUrl", "") or ""),
                     "catalog_status": "Resolved" if license_id in names else "Not in returned catalog"} for license_id in sorted(set(assigned))]
    return {"schema_version": 1, "org_id": org_id, "query": email, "person_id": person_id,
            "display_name": str(person.get("displayName", "") or ""), "emails": person["emails"],
            "login_enabled": person.get("loginEnabled") if isinstance(person.get("loginEnabled"), bool) else None,
            "licenses": licenses, "license_count": len(licenses),
            "warnings": ["Some assigned license IDs were not present in the returned organization catalog."] if any(item["catalog_status"] != "Resolved" for item in licenses) else [],
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "retention": "Latest successful lookup per configured organization only; not an archive."}


def _report_path(root, org_id):
    if not org_id:
        raise WebexError("WEBEX_ORG_ID is required to read saved lookup data.")
    return os.path.join(root, hashlib.sha256(org_id.encode()).hexdigest() + ".json")


def save_report(root, report):
    path = _report_path(root, report["org_id"])
    os.makedirs(root, exist_ok=True)
    if os.path.exists(path):
        load_report(root, report["org_id"])
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as handle:
            temp_path = handle.name
            json.dump(report, handle, ensure_ascii=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = ""
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def load_report(root, org_id):
    with open(_report_path(root, org_id), encoding="utf-8") as handle:
        report = json.load(handle)
    if not isinstance(report, dict) or report.get("schema_version") != 1 or report.get("org_id") != org_id or not isinstance(report.get("licenses"), list):
        raise WebexError("Saved Cisco Webex lookup is invalid and was not overwritten.")
    return report
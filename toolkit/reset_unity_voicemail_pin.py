import csv
import datetime
import io

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _make_unity_url(server, path):
    server = (server or "").strip()
    if server.startswith("http://") or server.startswith("https://"):
        base = server.rstrip("/")
    else:
        base = f"https://{server}"
    return f"{base}{path}"


def _unity_headers():
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _parse_error_text(response):
    text = (response.text or "").strip()
    if not text:
        return f"HTTP {response.status_code} with empty response body"
    return f"HTTP {response.status_code}: {text[:1200]}"


def _get_user_by_alias(session, unity_server, alias):
    query = f"(Alias is {alias})"
    url = _make_unity_url(unity_server, "/vmrest/users")
    response = session.get(url, headers=_unity_headers(), params={"query": query}, timeout=120)

    if response.status_code != 200:
        raise RuntimeError(f"User lookup failed: {_parse_error_text(response)}")

    if not response.text:
        return None

    try:
        data = response.json()
    except ValueError:
        return None

    users = data.get("User")
    if isinstance(users, dict):
        users = [users]
    if not isinstance(users, list):
        return None

    for user in users:
        if str(user.get("Alias", "")).lower() == alias.lower():
            return user

    return None


def _get_user_by_object_id(session, unity_server, object_id):
    url = _make_unity_url(unity_server, f"/vmrest/users/{object_id}")
    response = session.get(url, headers=_unity_headers(), timeout=120)

    if response.status_code != 200:
        raise RuntimeError(f"User detail lookup failed: {_parse_error_text(response)}")

    if not response.text:
        return None

    try:
        data = response.json()
    except ValueError:
        return None

    return data if isinstance(data, dict) else None


def _set_user_pin(session, unity_server, object_id, pin, must_change=True):
    url = _make_unity_url(unity_server, f"/vmrest/users/{object_id}/credential/pin")
    payload = {
        "Credentials": pin,
        "CredMustChange": str(bool(must_change)).lower(),
    }

    response = session.put(url, headers=_unity_headers(), json=payload, timeout=120)
    if response.status_code not in {200, 201, 204}:
        raise RuntimeError(f"Set PIN failed: {_parse_error_text(response)}")


def reset_unity_voicemail_pin(unity_server, unity_user, unity_pass, target_alias, new_pin):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reset_unity_voicemail_pin_{(target_alias or '').strip() or 'unknown'}_{ts}.csv"

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])

    if not (target_alias or "").strip():
        writer.writerow(["Validation", "Failed", "voicemail username is required"])
        return out.getvalue().encode("utf-8"), filename

    if not (new_pin or "").strip():
        writer.writerow(["Validation", "Failed", "new voicemail PIN is required"])
        return out.getvalue().encode("utf-8"), filename

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(unity_user, unity_pass)

    try:
        alias = target_alias.strip()
        mailbox = _get_user_by_alias(session, unity_server, alias)
        if not mailbox:
            raise RuntimeError(f"Voicemail box for {alias} not found. No reset was performed.")

        object_id = str(mailbox.get("ObjectId") or "").strip()
        if not object_id:
            raise RuntimeError(f"Unity mailbox '{alias}' was found, but ObjectId was missing")

        detail = _get_user_by_object_id(session, unity_server, object_id)
        if not detail:
            raise RuntimeError(f"Could not retrieve full Unity mailbox details for '{alias}'")

        mailbox_alias = str(detail.get("Alias") or alias).strip()
        extension = str(detail.get("DtmfAccessId") or "").strip()
        first_name = str(detail.get("FirstName") or "").strip()
        last_name = str(detail.get("LastName") or "").strip()

        writer.writerow([
            "Lookup Mailbox",
            "Success",
            f"Alias={mailbox_alias}; Extension={extension}; FirstName={first_name}; LastName={last_name}",
        ])

        _set_user_pin(session, unity_server, object_id, new_pin.strip(), must_change=True)
        writer.writerow([
            "Reset PIN",
            "Success",
            f"Reset voicemail PIN for {mailbox_alias}; must-change at next login enabled",
        ])

    except Exception as exc:
        writer.writerow(["Script", "Error", str(exc)])

    return out.getvalue().encode("utf-8"), filename

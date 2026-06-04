import csv
import datetime
import io
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_DEVICE_PREFIXES = ("CSF", "BOT", "TCT")


def _axl_post(session, cucm_host, soap_xml):
    url = f"https://{cucm_host}:8443/axl/"
    headers = {"Content-Type": "text/xml"}
    return session.post(url, data=soap_xml.encode("utf-8"), headers=headers, timeout=120)


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _find_child(elem, tag_name):
    for child in list(elem):
        if _strip_ns(child.tag) == tag_name:
            return child
    return None


def _find_first_text(elem, path_candidates):
    for path in path_candidates:
        cur = elem
        found = True
        for tag_name in path:
            cur = _find_child(cur, tag_name)
            if cur is None:
                found = False
                break
        if found and cur is not None and cur.text:
            value = cur.text.strip()
            if value:
                return value
    return ""


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


def _parse_unity_error_text(response):
    text = (response.text or "").strip()
    if not text:
        return f"HTTP {response.status_code} with empty response body"
    return f"HTTP {response.status_code}: {text[:1200]}"


def _build_update_phone_description_soap(phone_name, description):
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Body>
    <axl:updatePhone>
      <name>{escape(phone_name)}</name>
      <description>{escape(description)}</description>
    </axl:updatePhone>
  </soapenv:Body>
</soapenv:Envelope>"""


def _build_update_line_identity_soap(pattern, route_partition, display_name):
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Body>
    <axl:updateLine>
      <pattern>{escape(pattern)}</pattern>
      <routePartitionName>{escape(route_partition)}</routePartitionName>
      <alertingName>{escape(display_name)}</alertingName>
      <asciiAlertingName>{escape(display_name)}</asciiAlertingName>
            <display>{escape(display_name)}</display>
            <displayAscii>{escape(display_name)}</displayAscii>
    </axl:updateLine>
  </soapenv:Body>
</soapenv:Envelope>"""


def _get_user_details(session, cucm_host, username):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Body>
    <axl:getUser>
      <userid>{escape(username)}</userid>
    </axl:getUser>
  </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        raise RuntimeError(f"getUser failed with HTTP {response.status_code}: {response.text[:1000]}")

    root = ET.fromstring(response.text)
    user_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "user":
            user_node = elem
            break

    if user_node is None:
        raise RuntimeError("Could not locate user node in getUser response.")

    associated_devices = []
    assoc_parent = _find_child(user_node, "associatedDevices")
    if assoc_parent is not None:
        for child in list(assoc_parent):
            if _strip_ns(child.tag) == "device" and child.text and child.text.strip():
                associated_devices.append(child.text.strip())

    return {
        "userid": _find_first_text(user_node, [["userid"]]),
        "firstName": _find_first_text(user_node, [["firstName"]]),
        "lastName": _find_first_text(user_node, [["lastName"]]),
        "displayName": _find_first_text(user_node, [["displayName"]]),
        "associatedDevices": associated_devices,
    }


def _get_phone_details(session, cucm_host, phone_name):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Body>
    <axl:getPhone>
      <name>{escape(phone_name)}</name>
    </axl:getPhone>
  </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        raise RuntimeError(f"getPhone failed for {phone_name} with HTTP {response.status_code}: {response.text[:1000]}")

    root = ET.fromstring(response.text)
    phone_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "phone":
            phone_node = elem
            break

    if phone_node is None:
        raise RuntimeError(f"Could not locate phone node for {phone_name}.")

    line_entries = []
    lines_parent = _find_child(phone_node, "lines")
    if lines_parent is not None:
        for line in list(lines_parent):
            if _strip_ns(line.tag) != "line":
                continue
            pattern = _find_first_text(line, [["dirn", "pattern"]])
            partition = _find_first_text(line, [["dirn", "routePartitionName"]])
            if pattern:
                line_entries.append({"pattern": pattern, "partition": partition})

    return {"name": phone_name, "lines": line_entries}


def _get_unity_user_by_alias(session, unity_server, alias):
    query = f"(Alias is {alias})"
    url = _make_unity_url(unity_server, "/vmrest/users")
    response = session.get(url, headers=_unity_headers(), params={"query": query}, timeout=120)

    if response.status_code != 200:
        raise RuntimeError(f"Unity user lookup failed: {_parse_unity_error_text(response)}")

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


def _update_unity_user_profile(session, unity_server, object_id, display_name, smtp_address):
    url = _make_unity_url(unity_server, f"/vmrest/users/{object_id}")
    payload = {
        "DisplayName": display_name,
        "EmailAddress": smtp_address,
    }
    response = session.put(url, headers=_unity_headers(), json=payload, timeout=120)
    if response.status_code not in {200, 204}:
        raise RuntimeError(f"Unity profile update failed: {_parse_unity_error_text(response)}")


def _clean_email_part(value):
    value = (value or "").strip().lower()
    return re.sub(r"[^a-z0-9]", "", value)


def _build_smtp_address(first_name, last_name, userid):
    first = _clean_email_part(first_name)
    last = _clean_email_part(last_name)
    if first and last:
        return f"{first}.{last}"
    elif first or last:
        return first or last
    return _clean_email_part(userid) or "unknown.user"


def run_called_name_change(cucm_host, cucm_user, cucm_pass, unity_server, target_user):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"called_name_change_{(target_user or '').strip() or 'unknown'}_{ts}.csv"

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])

    clean_target_user = (target_user or "").strip()
    if not clean_target_user:
        writer.writerow(["Validation", "Failed", "target_user is required"])
        return out.getvalue().encode("utf-8"), filename

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    unity_session = requests.Session()
    unity_session.verify = False
    unity_session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    try:
        user = _get_user_details(session, cucm_host, clean_target_user)
        display_name = (user.get("displayName") or "").strip()
        if not display_name:
            display_name = " ".join(
                part for part in [user.get("firstName", "").strip(), user.get("lastName", "").strip()] if part
            ).strip()
        if not display_name:
            display_name = user.get("userid", clean_target_user)

        phone_description = f"CSF - {display_name}"

        smtp_address = _build_smtp_address(user.get("firstName", ""), user.get("lastName", ""), user.get("userid", ""))

        writer.writerow(["Lookup End User", "Success", f"Found {user.get('userid', clean_target_user)} with display name '{display_name}'"])
        writer.writerow(["Build SMTP Address", "Success", f"Using {smtp_address}"])

        jabber_devices = [
            d for d in (user.get("associatedDevices") or []) if d.upper().startswith(TARGET_DEVICE_PREFIXES)
        ]
        if not jabber_devices:
            writer.writerow(["Find Jabber Devices", "Skipped", "No CSF/BOT/TCT devices associated to this user"])
        else:
            writer.writerow(["Find Jabber Devices", "Success", f"Found {len(jabber_devices)} Jabber device(s)"])

        touched_lines = set()
        for device_name in jabber_devices:
            try:
                phone = _get_phone_details(session, cucm_host, device_name)

                phone_soap = _build_update_phone_description_soap(device_name, phone_description)
                phone_response = _axl_post(session, cucm_host, phone_soap)
                if phone_response.status_code == 200:
                    writer.writerow(["Update Phone Description", "Success", f"{device_name}: description set to '{phone_description}'"])
                else:
                    writer.writerow([
                        "Update Phone Description",
                        "Failed",
                        f"{device_name}: HTTP {phone_response.status_code}: {phone_response.text[:600]}",
                    ])
                    continue

                for line in phone.get("lines", []):
                    pattern = (line.get("pattern") or "").strip()
                    partition = (line.get("partition") or "").strip()
                    line_key = f"{pattern}|{partition}"
                    if not pattern or not partition or line_key in touched_lines:
                        continue

                    line_soap = _build_update_line_identity_soap(pattern, partition, display_name)
                    line_response = _axl_post(session, cucm_host, line_soap)
                    if line_response.status_code == 200:
                        touched_lines.add(line_key)
                        writer.writerow([
                            "Update Line Display Fields",
                            "Success",
                            f"{pattern}/{partition}: alerting and caller ID fields set to '{display_name}'",
                        ])
                    else:
                        writer.writerow([
                            "Update Line Display Fields",
                            "Failed",
                            f"{pattern}/{partition}: HTTP {line_response.status_code}: {line_response.text[:600]}",
                        ])
            except Exception as exc:
                writer.writerow(["Update Jabber Device", "Failed", f"{device_name}: {exc}"])

        try:
            mailbox = _get_unity_user_by_alias(unity_session, unity_server, user.get("userid", clean_target_user))
            if not mailbox:
                writer.writerow(["Update Unity Mailbox", "Failed", f"Mailbox not found for alias {clean_target_user}"])
            else:
                object_id = str(mailbox.get("ObjectId") or "").strip()
                if not object_id:
                    writer.writerow(["Update Unity Mailbox", "Failed", "Mailbox found but ObjectId missing"]) 
                else:
                    _update_unity_user_profile(unity_session, unity_server, object_id, display_name, smtp_address)
                    writer.writerow([
                        "Update Unity Mailbox",
                        "Success",
                        f"DisplayName='{display_name}', SMTP='{smtp_address}' on {unity_server}",
                    ])
        except Exception as exc:
            writer.writerow(["Update Unity Mailbox", "Failed", str(exc)])

    except Exception as exc:
        writer.writerow(["Called Name Change", "Failed", str(exc)])

    return out.getvalue().encode("utf-8"), filename
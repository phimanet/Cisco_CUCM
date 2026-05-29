import csv
import datetime
import io
import requests
import urllib3
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_DEVICE_PREFIX = "CSF"


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


def _soap_get_user(userid):
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Header/>
   <soapenv:Body>
      <axl:getUser>
         <userid>{escape(userid)}</userid>
      </axl:getUser>
   </soapenv:Body>
</soapenv:Envelope>"""


def _soap_get_phone(phone_name):
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:getPhone>
         <name>{escape(phone_name)}</name>
      </axl:getPhone>
   </soapenv:Body>
</soapenv:Envelope>"""


def _parse_user_details(xml_text, fallback_userid):
    root = ET.fromstring(xml_text)
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
        "userid": _find_first_text(user_node, [["userid"]]) or fallback_userid,
        "displayName": _find_first_text(user_node, [["displayName"]]),
        "firstName": _find_first_text(user_node, [["firstName"]]),
        "lastName": _find_first_text(user_node, [["lastName"]]),
        "associatedDevices": associated_devices,
    }


def _parse_phone_details(xml_text, fallback_name):
    root = ET.fromstring(xml_text)
    phone_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "phone":
            phone_node = elem
            break

    if phone_node is None:
        raise RuntimeError("Could not locate phone node in getPhone response.")

    lines = []
    lines_parent = _find_child(phone_node, "lines")
    if lines_parent is not None:
        for line in list(lines_parent):
            if _strip_ns(line.tag) != "line":
                continue
            idx = _find_first_text(line, [["index"]])
            pattern = _find_first_text(line, [["dirn", "pattern"]])
            partition = _find_first_text(line, [["dirn", "routePartitionName"]])
            label = _find_first_text(line, [["label"]])
            display = _find_first_text(line, [["display"]])
            if pattern:
                lines.append({
                    "index": idx,
                    "pattern": pattern,
                    "partition": partition,
                    "label": label,
                    "display": display,
                })

    return {
        "name": _find_first_text(phone_node, [["name"]]) or fallback_name,
        "lines": lines,
    }


def _normalize_userids(userids_text):
    userids = []
    seen = set()
    for raw in (userids_text or "").splitlines():
        userid = raw.strip()
        if not userid:
            continue
        lower = userid.lower()
        if lower in seen:
            continue
        seen.add(lower)
        userids.append(userid)
    return userids


def extract_rpo_phones(cucm_host, cucm_user, cucm_pass, userids_text):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"extract_rpo_phones_{ts}.csv"

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "User ID",
        "Display Name",
        "Device Name",
        "Line Index",
        "Pattern",
        "Route Partition",
        "Line Label",
        "Line Display",
        "Status",
        "Details",
    ])

    userids = _normalize_userids(userids_text)
    if not userids:
        writer.writerow(["", "", "", "", "", "", "", "", "Failed", "No user IDs were provided"])
        return out.getvalue().encode("utf-8"), filename

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    for userid in userids:
        try:
            user_resp = _axl_post(session, cucm_host, _soap_get_user(userid))
            if user_resp.status_code != 200:
                writer.writerow([
                    userid,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "Failed",
                    f"getUser HTTP {user_resp.status_code}: {user_resp.text[:600]}",
                ])
                continue

            user_details = _parse_user_details(user_resp.text, userid)
            display_name = (
                user_details.get("displayName")
                or " ".join(
                    part
                    for part in [user_details.get("firstName", ""), user_details.get("lastName", "")]
                    if part
                )
                or userid
            )

            csf_devices = [
                d for d in user_details.get("associatedDevices", []) if d.upper().startswith(TARGET_DEVICE_PREFIX)
            ]
            if not csf_devices:
                writer.writerow([
                    userid,
                    display_name,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "Skipped",
                    "No CSF devices associated to user",
                ])
                continue

            device_names = []
            line_indexes = []
            patterns = []
            partitions = []
            labels = []
            displays = []
            details_messages = []
            has_success_data = False

            for device_name in csf_devices:
                phone_resp = _axl_post(session, cucm_host, _soap_get_phone(device_name))
                if phone_resp.status_code != 200:
                    details_messages.append(
                        f"{device_name}: getPhone HTTP {phone_resp.status_code}: {phone_resp.text[:300]}"
                    )
                    continue

                phone_details = _parse_phone_details(phone_resp.text, device_name)
                resolved_device_name = phone_details.get("name", device_name)
                if resolved_device_name not in device_names:
                    device_names.append(resolved_device_name)

                lines = sorted(
                    phone_details.get("lines", []),
                    key=lambda item: int(item.get("index") or 9999),
                )
                if not lines:
                    details_messages.append(f"{resolved_device_name}: CSF device has no line entries")
                    continue

                for line in lines:
                    line_indexes.append(line.get("index", ""))
                    patterns.append(line.get("pattern", ""))
                    partitions.append(line.get("partition", ""))
                    labels.append(line.get("label", ""))
                    displays.append(line.get("display", ""))
                    has_success_data = True

            if has_success_data:
                writer.writerow([
                    userid,
                    display_name,
                    " | ".join(device_names),
                    " | ".join(line_indexes),
                    " | ".join(patterns),
                    " | ".join(partitions),
                    " | ".join(labels),
                    " | ".join(displays),
                    "Success",
                    " ; ".join(details_messages),
                ])
            else:
                writer.writerow([
                    userid,
                    display_name,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "Skipped",
                    " ; ".join(details_messages) or "No exportable rows generated for this user",
                ])

        except Exception as exc:
            writer.writerow([
                userid,
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "Error",
                str(exc),
            ])

    return out.getvalue().encode("utf-8"), filename

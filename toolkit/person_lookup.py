import requests
import urllib3
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape as xml_escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
AXL_NS = "http://www.cisco.com/AXL/API/15.0"

MAX_RESULTS = 100


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _find_child(elem, tag_name):
    for child in list(elem):
        if _strip_ns(child.tag) == tag_name:
            return child
    return None


def _find_first_text(elem, path_tags):
    for path in path_tags:
        cur = elem
        found = True
        for tag in path:
            cur = _find_child(cur, tag)
            if cur is None:
                found = False
                break
        if found and cur is not None and cur.text:
            v = cur.text.strip()
            if v:
                return v
    return ""


def _axl_post(session, cucm_host, soap_xml):
    url = f"https://{cucm_host}:8443/axl/"
    headers = {"Content-Type": "text/xml"}
    resp = session.post(
        url,
        data=soap_xml.encode("utf-8"),
        headers=headers,
        timeout=60,
        verify=False,
    )
    resp.raise_for_status()
    return resp.text


def _case_variants(value):
    clean = (value or "").strip()
    if not clean:
        return [""]

    ordered = []
    seen = set()
    for candidate in [clean, clean.lower(), clean.upper(), clean.title()]:
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)
    return ordered


def _soap_list_users(last_name, first_name=""):
    first_name_block = ""
    if (first_name or "").strip():
        first_name_block = f"\n      <firstName>%{xml_escape(first_name.strip())}%</firstName>"
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:listUser sequence="1">
      <searchCriteria>
        <lastName>%{xml_escape(last_name.strip())}%</lastName>{first_name_block}
      </searchCriteria>
      <returnedTags>
        <userid/>
        <firstName/>
        <lastName/>
      </returnedTags>
    </axl:listUser>
  </soapenv:Body>
</soapenv:Envelope>"""


def _soap_get_user(userid):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getUser sequence="1">
      <userid>{xml_escape(userid)}</userid>
    </axl:getUser>
  </soapenv:Body>
</soapenv:Envelope>"""


def _soap_get_phone(phone_name):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getPhone sequence="1">
      <name>{xml_escape(phone_name)}</name>
    </axl:getPhone>
  </soapenv:Body>
</soapenv:Envelope>"""


def _soap_select_cm_devices(device_names):
        select_items = "".join(
                f"<item><Item>{xml_escape(name)}</Item></item>"
                for name in (device_names or [])
                if (name or "").strip()
        )
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ris="http://schemas.cisco.com/ast/soap">
    <soapenv:Header/>
    <soapenv:Body>
        <ris:selectCmDevice>
            <StateInfo></StateInfo>
            <CmSelectionCriteria>
                <MaxReturnedDevices>2000</MaxReturnedDevices>
                <DeviceClass>Phone</DeviceClass>
                <Model>255</Model>
                <Status>Any</Status>
                <NodeName></NodeName>
                <SelectBy>Name</SelectBy>
                <SelectItems>{select_items}</SelectItems>
                <Protocol>Any</Protocol>
                <DownloadStatus>Any</DownloadStatus>
            </CmSelectionCriteria>
        </ris:selectCmDevice>
    </soapenv:Body>
</soapenv:Envelope>"""


def _parse_phone_lines(xml_text):
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []
    for elem in root.iter():
        if _strip_ns(elem.tag) == "phone":
            phone_node = elem
            lines_parent = _find_child(phone_node, "lines")
            if lines_parent is None:
                return []
            lines = []
            for line in list(lines_parent):
                if _strip_ns(line.tag) != "line":
                    continue
                pattern = _find_first_text(line, [["dirn", "pattern"]])
                if pattern:
                    lines.append(pattern)
            return lines
    return []


def _device_type(name):
    upper = (name or "").upper()
    if upper.startswith("CSF"):
        return "CSF (Jabber Laptop)"
    if upper.startswith("TCT"):
        return "TCT (Jabber iPhone)"
    if upper.startswith("BOT"):
        return "BOT (Jabber Android)"
    if upper.startswith("TAB"):
        return "TAB (Jabber Tablet)"
    return "Phone"


def _ris_fetch_device_statuses(session, cucm_host, device_names):
    clean_names = [name.strip() for name in (device_names or []) if (name or "").strip()]
    if not clean_names:
        return {}

    soap_xml = _soap_select_cm_devices(sorted(set(clean_names)))
    ris_urls = [
        f"https://{cucm_host}:8443/realtimeservice2/services/RISService70",
        f"https://{cucm_host}:8443/realtimeservice/services/RISService70",
    ]

    response_text = ""
    for ris_url in ris_urls:
        try:
            response = session.post(
                ris_url,
                data=soap_xml.encode("utf-8"),
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "CUCM:DB ver=7.0 selectCmDevice",
                },
                timeout=60,
                verify=False,
            )
            if response.status_code != 200:
                continue
            response_text = response.text or ""
            break
        except Exception:
            continue

    if not response_text:
        return {}

    try:
        root = ET.fromstring(response_text)
    except Exception:
        return {}

    statuses = {}
    timestamp_candidates = {
        "TimeStamp",
        "LastStatusChange",
        "LastStatusChangeTime",
        "LastRegisteredTime",
        "LastRegistrationTime",
    }

    for elem in root.iter():
        if _strip_ns(elem.tag) != "CmDevice":
            continue

        device_name = _find_first_text(elem, [["Name"]])
        if not device_name:
            continue

        status_text = _find_first_text(elem, [["Status"]]) or "Unknown"
        last_registered = ""

        for child in list(elem):
            tag_name = _strip_ns(child.tag)
            text = (child.text or "").strip()
            if not text:
                continue
            if tag_name in timestamp_candidates:
                last_registered = text
                break

        if not last_registered:
            for child in list(elem):
                tag_name = _strip_ns(child.tag)
                text = (child.text or "").strip()
                if text and "time" in tag_name.lower():
                    last_registered = text
                    break

        statuses[device_name] = {
            "registration_status": status_text,
            "last_registered": last_registered,
        }

    return statuses


def search_persons_by_name(cucm_host, cucm_user, cucm_pass, last_name, first_name=""):
    """
    Search CUCM end users by last name (required) and optional first name.
    Returns a list of user dicts:
            userid, first_name, last_name, display_name, email, telephone,
      primary_extension, devices (list of {name, type, extensions}).
    """
    last_name = (last_name or "").strip()
    if not last_name:
        raise ValueError("last_name is required")

    session = requests.Session()
    session.trust_env = False
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    userids = []
    seen = set()

    # 1. List users matching the name, probing case variants to avoid case-sensitive misses.
    first_name_variants = _case_variants(first_name)
    for last_variant in _case_variants(last_name):
        for first_variant in first_name_variants:
            list_xml = _soap_list_users(last_variant, first_variant)
            list_resp = _axl_post(session, cucm_host, list_xml)
            list_root = ET.fromstring(list_resp)

            for elem in list_root.iter():
                if _strip_ns(elem.tag) != "user":
                    continue
                uid_elem = _find_child(elem, "userid")
                uid = (uid_elem.text or "").strip() if uid_elem is not None else ""
                if not uid:
                    continue

                uid_key = uid.casefold()
                if uid_key in seen:
                    continue

                seen.add(uid_key)
                userids.append(uid)
                if len(userids) >= MAX_RESULTS:
                    break

            if len(userids) >= MAX_RESULTS:
                break
        if len(userids) >= MAX_RESULTS:
            break

    if not userids:
        return []

    user_records = []
    all_device_names = set()
    for uid in userids:
        try:
            user_xml = _axl_post(session, cucm_host, _soap_get_user(uid))
            user_root = ET.fromstring(user_xml)
        except Exception:
            continue

        user_node = None
        for elem in user_root.iter():
            if _strip_ns(elem.tag) == "user":
                user_node = elem
                break
        if user_node is None:
            continue

        # Collect associated device names
        associated = []
        assoc_parent = _find_child(user_node, "associatedDevices")
        if assoc_parent is not None:
            for child in list(assoc_parent):
                if _strip_ns(child.tag) == "device" and child.text and child.text.strip():
                    associated.append(child.text.strip())
                    all_device_names.add(child.text.strip())

        user_records.append({
            "userid": _find_first_text(user_node, [["userid"]]) or uid,
            "first_name": _find_first_text(user_node, [["firstName"]]),
            "last_name": _find_first_text(user_node, [["lastName"]]),
            "display_name": _find_first_text(user_node, [["displayName"]]),
            "email": _find_first_text(user_node, [["mailid"]]),
            "telephone": _find_first_text(user_node, [["telephoneNumber"], ["telephone"]]),
            "associated": associated,
        })

    device_status_map = _ris_fetch_device_statuses(session, cucm_host, sorted(all_device_names))

    results = []
    phone_lines_cache = {}
    for user in user_records:
        associated = user.get("associated", [])
        devices = []
        primary_ext = ""
        for dev_name in associated:
            if dev_name in phone_lines_cache:
                lines = phone_lines_cache[dev_name]
            else:
                try:
                    phone_xml = _axl_post(session, cucm_host, _soap_get_phone(dev_name))
                    lines = _parse_phone_lines(phone_xml)
                except Exception:
                    lines = []
                phone_lines_cache[dev_name] = lines

            device_status = device_status_map.get(dev_name, {})
            devices.append({
                "name": dev_name,
                "type": _device_type(dev_name),
                "extensions": lines,
                "registration_status": device_status.get("registration_status", "Unknown"),
                "last_registered": device_status.get("last_registered", ""),
            })
            if not primary_ext and lines:
                primary_ext = lines[0]

        results.append({
            "userid": user.get("userid", ""),
            "first_name": user.get("first_name", ""),
            "last_name": user.get("last_name", ""),
            "display_name": user.get("display_name", ""),
            "email": user.get("email", ""),
            "telephone": user.get("telephone", ""),
            "primary_extension": primary_ext,
            "devices": devices,
        })

    return results

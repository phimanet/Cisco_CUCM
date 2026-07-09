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


def search_persons_by_name(cucm_host, cucm_user, cucm_pass, last_name, first_name=""):
    """
    Search CUCM end users by last name (required) and optional first name.
    Returns a list of user dicts:
            userid, first_name, last_name, display_name, title, email, telephone,
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

    results = []
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

        # Look up each device for its lines
        devices = []
        primary_ext = ""
        for dev_name in associated:
            try:
                phone_xml = _axl_post(session, cucm_host, _soap_get_phone(dev_name))
                lines = _parse_phone_lines(phone_xml)
            except Exception:
                lines = []
            devices.append({
                "name": dev_name,
                "type": _device_type(dev_name),
                "extensions": lines,
            })
            if not primary_ext and lines:
                primary_ext = lines[0]

        results.append({
            "userid": _find_first_text(user_node, [["userid"]]) or uid,
            "first_name": _find_first_text(user_node, [["firstName"]]),
            "last_name": _find_first_text(user_node, [["lastName"]]),
            "display_name": _find_first_text(user_node, [["displayName"]]),
            "title": _find_first_text(user_node, [["title"]]),
            "email": _find_first_text(user_node, [["mailid"]]),
            "telephone": _find_first_text(user_node, [["telephoneNumber"], ["telephone"]]),
            "primary_extension": primary_ext,
            "devices": devices,
        })

    return results

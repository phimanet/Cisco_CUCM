import requests
import urllib3
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape as xml_escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
AXL_NS = "http://www.cisco.com/AXL/API/15.0"


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
    resp = session.post(url, data=soap_xml.encode("utf-8"), headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.text


def _soap_get_line(pattern, route_partition=""):
    partition_block = ""
    if route_partition.strip():
        partition_block = f"\n         <routePartitionName>{xml_escape(route_partition.strip())}</routePartitionName>"
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getLine sequence="1">
      <pattern>{xml_escape(pattern.strip())}</pattern>{partition_block}
    </axl:getLine>
  </soapenv:Body>
</soapenv:Envelope>"""


def _soap_list_lines(pattern):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:listLine sequence="1">
      <searchCriteria>
        <pattern>%{xml_escape(pattern.strip())}%</pattern>
      </searchCriteria>
      <returnedTags>
        <pattern/>
        <routePartitionName/>
        <description/>
      </returnedTags>
    </axl:listLine>
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


def _get_line_associated_devices(session, cucm_host, pattern, route_partition=""):
    """Get list of device names assigned to a specific DN."""
    xml_text = _axl_post(session, cucm_host, _soap_get_line(pattern, route_partition))
    root = ET.fromstring(xml_text)

    devices = []
    for elem in root.iter():
        if _strip_ns(elem.tag) == "line":
            assoc = _find_child(elem, "associatedDevices")
            if assoc is not None:
                for child in list(assoc):
                    if _strip_ns(child.tag) == "device" and child.text and child.text.strip():
                        devices.append(child.text.strip())
            break
    return devices


def _get_phone_owner(session, cucm_host, phone_name):
    """Get the ownerUserName from a phone device."""
    try:
        xml_text = _axl_post(session, cucm_host, _soap_get_phone(phone_name))
    except Exception:
        return None, []
    root = ET.fromstring(xml_text)
    phone_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "phone":
            phone_node = elem
            break
    if phone_node is None:
        return None, []
    owner = _find_first_text(phone_node, [["ownerUserName"]])
    # collect all line patterns on this phone
    lines = []
    lines_parent = _find_child(phone_node, "lines")
    if lines_parent is not None:
        for line in list(lines_parent):
            if _strip_ns(line.tag) != "line":
                continue
            pat = _find_first_text(line, [["dirn", "pattern"]])
            part = _find_first_text(line, [["dirn", "routePartitionName"]])
            if pat:
                lines.append({"pattern": pat, "partition": part})
    return owner or None, lines


def _get_user_info(session, cucm_host, userid):
    try:
        xml_text = _axl_post(session, cucm_host, _soap_get_user(userid))
    except Exception:
        return {}
    root = ET.fromstring(xml_text)
    user_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "user":
            user_node = elem
            break
    if user_node is None:
        return {}
    return {
        "userid": _find_first_text(user_node, [["userid"]]) or userid,
        "first_name": _find_first_text(user_node, [["firstName"]]),
        "last_name": _find_first_text(user_node, [["lastName"]]),
        "display_name": _find_first_text(user_node, [["displayName"]]),
        "email": _find_first_text(user_node, [["mailid"]]),
    }


def lookup_extension_owner(cucm_host, cucm_user, cucm_pass, pattern):
    """
    Reverse lookup: given a DN pattern, find which device(s) and user(s) own it.
    Returns a dict:
      {
        "pattern": str,
        "matches": [
          {
            "device_name": str,
            "device_type": str,
            "all_lines": [...],
            "owner_userid": str,
            "user": { userid, first_name, last_name, display_name, email }
          }
        ]
      }
    """
    pattern = (pattern or "").strip()
    if not pattern:
        raise ValueError("pattern is required")

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    # 1. List matching lines (supports partial/wildcard input)
    list_xml = _axl_post(session, cucm_host, _soap_list_lines(pattern))
    list_root = ET.fromstring(list_xml)

    matched_lines = []
    seen_patterns = set()
    for elem in list_root.iter():
        if _strip_ns(elem.tag) == "line":
            pat = _find_first_text(elem, [["pattern"]])
            part = _find_first_text(elem, [["routePartitionName"]])
            if pat and pat not in seen_patterns:
                seen_patterns.add(pat)
                matched_lines.append({"pattern": pat, "partition": part})

    if not matched_lines:
        return {"pattern": pattern, "matches": []}

    matches = []
    for line in matched_lines:
        try:
            devices = _get_line_associated_devices(
                session, cucm_host, line["pattern"], line["partition"]
            )
        except Exception:
            devices = []

        if not devices:
            # DN exists but is unassigned
            matches.append({
                "pattern": line["pattern"],
                "partition": line["partition"],
                "device_name": None,
                "device_type": None,
                "all_lines": [],
                "owner_userid": None,
                "user": {},
            })
            continue

        for dev in devices:
            owner_userid, all_lines = _get_phone_owner(session, cucm_host, dev)
            user_info = {}
            if owner_userid:
                user_info = _get_user_info(session, cucm_host, owner_userid)

            matches.append({
                "pattern": line["pattern"],
                "partition": line["partition"],
                "device_name": dev,
                "device_type": _device_type(dev),
                "all_lines": all_lines,
                "owner_userid": owner_userid,
                "user": user_info,
            })

    return {"pattern": pattern, "matches": matches}


def check_user_devices(cucm_host, cucm_user, cucm_pass, target_user):
    """
    Check which Jabber device types (CSF/TCT/BOT) a user already has.
    Returns dict with booleans: has_csf, has_tct, has_bot, devices list.
    """
    target_user = (target_user or "").strip()
    if not target_user:
        raise ValueError("target_user is required")

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    xml_text = _axl_post(session, cucm_host, _soap_get_user(target_user))
    root = ET.fromstring(xml_text)

    user_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "user":
            user_node = elem
            break
    if user_node is None:
        raise RuntimeError(f"User not found: {target_user}")

    associated = []
    assoc_parent = _find_child(user_node, "associatedDevices")
    if assoc_parent is not None:
        for child in list(assoc_parent):
            if _strip_ns(child.tag) == "device" and child.text and child.text.strip():
                associated.append(child.text.strip())

    devices = [{"name": d, "type": _device_type(d)} for d in associated]

    return {
        "userid": _find_first_text(user_node, [["userid"]]) or target_user,
        "display_name": _find_first_text(user_node, [["displayName"]]),
        "has_csf": any(d.upper().startswith("CSF") for d in associated),
        "has_tct": any(d.upper().startswith("TCT") for d in associated),
        "has_bot": any(d.upper().startswith("BOT") for d in associated),
        "devices": devices,
    }

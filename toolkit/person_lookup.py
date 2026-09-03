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


def lookup_person_email_by_userid(cucm_host, cucm_user, cucm_pass, userid):
    """Return one CUCM user's email by userid for workflows that need a reliable address."""
    clean_userid = (userid or "").strip()
    if not clean_userid:
        return ""

    session = requests.Session()
    session.trust_env = False
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)
    try:
        response = _axl_post(session, cucm_host, _soap_get_user(clean_userid))
        root = ET.fromstring(response)
    except Exception:
        return ""

    for elem in root.iter():
        if _strip_ns(elem.tag).lower() in {"mailid", "email"} and (elem.text or "").strip():
            return elem.text.strip()
    return ""


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


def _soap_list_trans_pattern_by_description(description_fragment):
        return f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"{SOAPENV_NS}\" xmlns:axl=\"{AXL_NS}\">
    <soapenv:Header/>
    <soapenv:Body>
        <axl:listTransPattern sequence=\"1\">
            <searchCriteria>
                <description>%{xml_escape(description_fragment.strip())}%</description>
            </searchCriteria>
            <returnedTags>
                <pattern/>
                <description/>
                <calledPartyTransformationMask/>
            </returnedTags>
        </axl:listTransPattern>
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


def _parse_phone_status(xml_text):
    if not xml_text:
        return ""
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return ""

    for elem in root.iter():
        if _strip_ns(elem.tag) != "phone":
            continue

        def _child_text(parent, names):
            for child in list(parent):
                tag = _strip_ns(child.tag).lower()
                if tag in names and child.text:
                    value = child.text.strip()
                    if value:
                        return value
            return ""

        # Prefer human-readable status text when present.
        status_text = _child_text(elem, {"status", "devicestatus"})
        if status_text:
            return status_text

        # Fallback to numeric tkstatus if CUCM omits status label.
        tkstatus_text = _child_text(elem, {"tkstatus", "statusenum"})
        if tkstatus_text:
            return tkstatus_text

        return ""
    return ""


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


def _parse_trans_patterns(xml_text):
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []

    rows = []
    for elem in root.iter():
        if _strip_ns(elem.tag) != "transPattern":
            continue
        pattern = _find_first_text(elem, [["pattern"]])
        description = _find_first_text(elem, [["description"]])
        mask = _find_first_text(elem, [["calledPartyTransformationMask"], ["calledPartyTransformMask"]])
        if pattern:
            rows.append({
                "pattern": pattern,
                "description": description,
                "mask": mask,
            })
    return rows


def _lookup_translated_number(session, cucm_host, first_name, last_name, extension_candidates):
    clean_first = (first_name or "").strip()
    clean_last = (last_name or "").strip()
    mask_candidates = {str(ext or "").strip() for ext in (extension_candidates or []) if str(ext or "").strip()}
    if not clean_first or not clean_last or not mask_candidates:
        return ""

    description_fragment = f"{clean_first} {clean_last}".strip()
    try:
        list_xml = _axl_post(session, cucm_host, _soap_list_trans_pattern_by_description(description_fragment))
    except Exception:
        return ""

    matches = []
    for row in _parse_trans_patterns(list_xml):
        if (row.get("mask") or "").strip() in mask_candidates:
            matches.append((row.get("pattern") or "").strip())

    if not matches:
        return ""

    # Keep a stable, deterministic selection if multiple patterns match the same person/mask.
    return sorted(set(matches))[0]


def _soap_execute_sql(sql: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:executeSQLQuery>
      <sql>{xml_escape(sql)}</sql>
    </axl:executeSQLQuery>
  </soapenv:Body>
</soapenv:Envelope>"""


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

    # Escape single quotes for SQL safety
    def _q(value: str) -> str:
        return value.strip().replace("'", "''")

    where_parts = [f"LOWER(u.lastname) LIKE '%{_q(last_name.lower())}%'"]
    clean_first = (first_name or "").strip()
    if clean_first:
        where_parts.append(f"LOWER(u.firstname) LIKE '%{_q(clean_first.lower())}%'")

    sql = (
        "SELECT u.userid AS userid, u.firstname AS firstname, u.lastname AS lastname, "
        "u.displayname AS displayname, u.title AS title, u.mailid AS mailid, "
        "u.telephonenumber AS telephonenumber, "
        "d.name AS device_name, n.dnorpattern AS extension, "
        "dm.numplanindex AS line_index "
        "FROM enduser u "
        "LEFT OUTER JOIN enduserdevicemap edm ON edm.fkenduser = u.pkid "
        "LEFT OUTER JOIN device d ON d.pkid = edm.fkdevice "
        "LEFT OUTER JOIN devicenumplanmap dm ON dm.fkdevice = d.pkid "
        "LEFT OUTER JOIN numplan n ON n.pkid = dm.fknumplan "
        f"WHERE {' AND '.join(where_parts)} "
        "ORDER BY u.lastname, u.firstname, u.userid, d.name, dm.numplanindex"
    )

    try:
        resp = _axl_post(session, cucm_host, _soap_execute_sql(sql))
        root = ET.fromstring(resp)
    except Exception:
        return []

    # Aggregate one SQL row per (user, device, line) into user dicts
    users: dict = {}
    user_order: list = []

    for elem in root.iter():
        if _strip_ns(elem.tag) != "row":
            continue
        r: dict = {}
        for child in list(elem):
            r[_strip_ns(child.tag)] = (child.text or "").strip()

        uid = r.get("userid", "").strip()
        if not uid:
            continue

        if uid not in users:
            users[uid] = {
                "userid": uid,
                "first_name": r.get("firstname", ""),
                "last_name": r.get("lastname", ""),
                "display_name": r.get("displayname", ""),
                "title": r.get("title", ""),
                "email": r.get("mailid", ""),
                "telephone": r.get("telephonenumber", ""),
                "primary_extension": "",
                "translated_number": "",
                "_devices_map": {},
            }
            user_order.append(uid)

        device_name = r.get("device_name", "").strip()
        extension = r.get("extension", "").strip()

        if device_name:
            dmap = users[uid]["_devices_map"]
            if device_name not in dmap:
                dmap[device_name] = {
                    "name": device_name,
                    "type": _device_type(device_name),
                    "extensions": [],
                    "status": "",
                }
            if extension and extension not in dmap[device_name]["extensions"]:
                dmap[device_name]["extensions"].append(extension)

    results = []
    for uid in user_order[:MAX_RESULTS]:
        u = users[uid]
        devices_list = list(u.pop("_devices_map").values())

        primary_ext = ""
        all_exts: list = []
        for d in devices_list:
            all_exts.extend(d["extensions"])
            if not primary_ext and d["extensions"]:
                primary_ext = d["extensions"][0]

        u["primary_extension"] = primary_ext
        u["devices"] = devices_list
        u["translated_number"] = _lookup_translated_number(
            session, cucm_host,
            u["first_name"], u["last_name"],
            ([primary_ext] if primary_ext else []) + all_exts,
        )
        results.append(u)

    return results

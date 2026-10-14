import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import requests
from requests.auth import HTTPBasicAuth


PARTITION = "ENT_DEVICE_PT"
PAGE_SIZE = 1000
MAX_PAGES = 100
JABBER_DEVICE_PREFIXES = ("CSF", "TCT", "BOT", "TAB")
_SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
_AXL_NS = "http://www.cisco.com/AXL/API/15.0"


def _validated_userid(userid):
    clean = str(userid or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", clean):
        raise ValueError("Choose a valid CUCM user ID.")
    return clean


def _validated_extension(extension):
    clean = str(extension or "").strip()
    if not re.fullmatch(r"[0-9]{3,15}", clean):
        raise ValueError("The candidate extension must contain 3-15 digits.")
    return clean


def _escape_sql(value):
    return str(value or "").replace("'", "''")


def _select_body(association, userid=""):
    if association == "owner":
        device_join = "INNER JOIN device d ON d.fkenduser = u.pkid "
    elif association == "associated":
        device_join = (
            "INNER JOIN enduserdevicemap edm ON edm.fkenduser = u.pkid "
            "INNER JOIN device d ON d.pkid = edm.fkdevice "
        )
    else:
        raise ValueError("Unsupported Jabber device association.")

    user_filter = ""
    if userid:
        user_filter = f"AND LOWER(u.userid) = LOWER('{_escape_sql(userid)}') "

    return (
        "u.userid AS userid, u.firstname AS first_name, u.lastname AS last_name, "
        "u.mailid AS email, d.name AS device_name, "
        "COALESCE(n.dnorpattern, '') AS jabber_extension, "
        "COALESCE(r.name, '') AS jabber_partition "
        "FROM enduser u "
        + device_join
        + "LEFT OUTER JOIN devicenumplanmap dm ON dm.fkdevice = d.pkid "
        + "LEFT OUTER JOIN numplan n ON n.pkid = dm.fknumplan "
        + "LEFT OUTER JOIN routepartition r ON r.pkid = n.fkroutepartition "
        + "LEFT OUTER JOIN endusernumplanmap primary_map "
        + "ON primary_map.fkenduser = u.pkid AND primary_map.tkdnusage = 1 "
        + "WHERE primary_map.pkid IS NULL "
        + "AND (d.name LIKE 'CSF%' OR d.name LIKE 'TCT%' OR "
        + "d.name LIKE 'BOT%' OR d.name LIKE 'TAB%') "
        + user_filter
        + "ORDER BY u.userid, d.name, n.dnorpattern"
    )


def _iter_sql_rows(cucm_host, cucm_user, cucm_pass, sql_executor, select_body):
    for page in range(MAX_PAGES):
        offset = page * PAGE_SIZE
        sql = f"SELECT SKIP {offset} FIRST {PAGE_SIZE} {select_body}"
        batch = sql_executor(cucm_host, cucm_user, cucm_pass, sql)
        for row in batch:
            yield row
        if len(batch) < PAGE_SIZE:
            return
    raise RuntimeError("Jabber End User search exceeded the safe page limit; narrow the search.")


def find_missing_primary_extension_users(cucm_host, cucm_user, cucm_pass, sql_executor, userid=""):
    clean_userid = _validated_userid(userid) if str(userid or "").strip() else ""
    users = {}
    seen_lines = set()

    for association in ("owner", "associated"):
        select_body = _select_body(association, clean_userid)
        for row in _iter_sql_rows(cucm_host, cucm_user, cucm_pass, sql_executor, select_body):
            user_id = str(row.get("userid", "") or "").strip()
            device_name = str(row.get("device_name", "") or "").strip()
            if not user_id or not device_name:
                continue

            user = users.setdefault(user_id.casefold(), {
                "userid": user_id,
                "first_name": str(row.get("first_name", "") or "").strip(),
                "last_name": str(row.get("last_name", "") or "").strip(),
                "name": " ".join(part for part in (
                    str(row.get("first_name", "") or "").strip(),
                    str(row.get("last_name", "") or "").strip(),
                ) if part),
                "email": str(row.get("email", "") or "").strip(),
                "primary_extension": "",
                "jabber_devices": set(),
                "jabber_lines": {},
                "eligible_extensions": set(),
            })
            user["jabber_devices"].add(device_name)

            extension = str(row.get("jabber_extension", "") or "").strip()
            partition = str(row.get("jabber_partition", "") or "").strip()
            line_key = (user_id.casefold(), device_name, extension, partition)
            if line_key in seen_lines:
                continue
            seen_lines.add(line_key)
            if not extension:
                continue
            user["jabber_lines"][line_key] = {
                "device_name": device_name,
                "extension": extension,
                "partition": partition,
            }
            if partition.casefold() == PARTITION.casefold():
                user["eligible_extensions"].add(extension)

    results = []
    for user in users.values():
        eligible = sorted(user.pop("eligible_extensions"))
        user["jabber_devices"] = sorted(user["jabber_devices"], key=str.casefold)
        user["jabber_lines"] = sorted(
            user["jabber_lines"].values(),
            key=lambda line: (line["device_name"].casefold(), line["extension"], line["partition"].casefold()),
        )
        user["eligible_extensions"] = eligible
        user["fix_allowed"] = len(eligible) == 1
        user["fix_extension"] = eligible[0] if len(eligible) == 1 else ""
        if not eligible:
            user["fix_reason"] = "No associated Jabber line in ENT_DEVICE_PT."
        elif len(eligible) > 1:
            user["fix_reason"] = "Multiple Jabber lines in ENT_DEVICE_PT; manual selection is required."
        else:
            user["fix_reason"] = ""
        results.append(user)

    return sorted(results, key=lambda user: (user["last_name"].casefold(), user["first_name"].casefold(), user["userid"].casefold()))


def _local_name(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _post_axl(session, cucm_host, soap, operation):
    response = session.post(
        f"https://{cucm_host}:8443/axl/",
        data=soap.encode("utf-8"),
        headers={"Content-Type": "text/xml"},
        timeout=60,
        verify=False,
    )
    if not 200 <= response.status_code < 300:
        raise RuntimeError(f"{operation} failed HTTP {response.status_code}.")
    try:
        root = ET.fromstring(response.text or "")
    except ET.ParseError as exc:
        raise RuntimeError(f"{operation} returned invalid XML.") from exc
    fault = next((elem.text for elem in root.iter() if _local_name(elem.tag) == "faultstring" and elem.text), "")
    if fault:
        raise RuntimeError(f"{operation} returned an AXL fault: {fault.strip()[:400]}")
    return root


def _read_primary_extension(session, cucm_host, userid):
    soap = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{_SOAP_ENV}" xmlns:axl="{_AXL_NS}">
  <soapenv:Header/><soapenv:Body>
    <axl:getUser sequence="1"><userid>{escape(userid)}</userid>
      <returnedTags><userid/><primaryExtension><pattern/><routePartitionName/></primaryExtension></returnedTags>
    </axl:getUser>
  </soapenv:Body>
</soapenv:Envelope>'''
    root = _post_axl(session, cucm_host, soap, "getUser")
    user = next((elem for elem in root.iter() if _local_name(elem.tag) == "user"), None)
    if user is None:
        raise RuntimeError("getUser returned no End User record.")
    returned_userid = next((elem.text.strip() for elem in user.iter() if _local_name(elem.tag) == "userid" and elem.text), "")
    if returned_userid.casefold() != userid.casefold():
        raise RuntimeError("getUser returned a different End User identity.")
    primary = next((elem for elem in user if _local_name(elem.tag) == "primaryExtension"), None)
    pattern = ""
    partition = ""
    if primary is not None:
        for elem in primary.iter():
            name = _local_name(elem.tag)
            if name == "pattern" and elem.text:
                pattern = elem.text.strip()
            elif name == "routePartitionName" and elem.text:
                partition = elem.text.strip()
    return pattern, partition


def fix_primary_extension(cucm_host, cucm_user, cucm_pass, userid, extension, session_factory=requests.Session):
    userid = _validated_userid(userid)
    extension = _validated_extension(extension)
    session = session_factory()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    current_pattern, current_partition = _read_primary_extension(session, cucm_host, userid)
    if current_pattern:
        raise RuntimeError(
            f"Primary Extension is no longer blank ({current_pattern}/{current_partition}); refresh the candidate list."
        )

    soap = f'''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{_SOAP_ENV}" xmlns:axl="{_AXL_NS}">
  <soapenv:Header/><soapenv:Body>
    <axl:updateUser sequence="1"><userid>{escape(userid)}</userid>
      <primaryExtension><pattern>{extension}</pattern><routePartitionName>{PARTITION}</routePartitionName></primaryExtension>
    </axl:updateUser>
  </soapenv:Body>
</soapenv:Envelope>'''

    try:
        _post_axl(session, cucm_host, soap, "updateUser Primary Extension")
    except Exception:
        try:
            verified_pattern, verified_partition = _read_primary_extension(session, cucm_host, userid)
        except Exception:
            raise
        if verified_pattern == extension and verified_partition.casefold() == PARTITION.casefold():
            return {"userid": userid, "extension": extension, "partition": PARTITION, "verified": True}
        raise

    verified_pattern, verified_partition = _read_primary_extension(session, cucm_host, userid)
    if verified_pattern != extension or verified_partition.casefold() != PARTITION.casefold():
        raise RuntimeError("CUCM did not confirm the requested Primary Extension after update.")
    return {"userid": userid, "extension": extension, "partition": PARTITION, "verified": True}
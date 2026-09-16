import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
AXL_NS = "http://www.cisco.com/AXL/API/15.0"
MAX_CANDIDATE_ROWS = 10000
MAX_RESULTS = 500

PATTERN_USAGE_NAMES = {
    "2": "Directory Number",
    "3": "Translation Pattern",
    "15": "Translation Pattern",
}


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _sql_literal(value):
    return str(value or "").replace("'", "''")


def _normalize_number(value):
    text = str(value or "").strip()
    if text.startswith("+"):
        return "+" + re.sub(r"\D", "", text[1:])
    return "".join(character for character in text if character.isdigit() or character in "*#")


def _pattern_regex(pattern):
    source = str(pattern or "").strip()
    if not source:
        return None

    parts = []
    index = 0
    while index < len(source):
        character = source[index]
        if character == "\\" and index + 1 < len(source):
            parts.append(re.escape(source[index + 1]))
            index += 2
            continue
        if character == "X":
            parts.append(r"\d")
        elif character == "!":
            parts.append(r"\d+")
        elif character == "?":
            parts.append(r"\d*")
        elif character == "@":
            parts.append(r"\d+")
        elif character == ".":
            pass
        elif character == "[":
            end = source.find("]", index + 1)
            if end < 0:
                parts.append(re.escape(character))
            else:
                char_class = source[index + 1:end]
                if re.fullmatch(r"[0-9\-,]+", char_class):
                    parts.append("[" + char_class + "]")
                else:
                    parts.append(re.escape(source[index:end + 1]))
                index = end
        else:
            parts.append(re.escape(character))
        index += 1

    try:
        return re.compile("^" + "".join(parts) + "$")
    except re.error:
        return None


def _match_kind(pattern, number):
    if pattern == number:
        return "Exact"
    if str(pattern or "").startswith(number):
        return "Begins With"
    return ""


def _soap_execute_sql(sql):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:executeSQLQuery>
      <sql>{xml_escape(sql)}</sql>
    </axl:executeSQLQuery>
  </soapenv:Body>
</soapenv:Envelope>"""


def _execute_sql(session, cucm_host, sql):
    response = session.post(
        f"https://{cucm_host}:8443/axl/",
        data=_soap_execute_sql(sql).encode("utf-8"),
        headers={"Content-Type": "text/xml"},
        timeout=60,
        verify=False,
    )
    if response.status_code != 200:
        raise RuntimeError(f"executeSQLQuery failed HTTP {response.status_code}: {response.text[:800]}")

    rows = []
    root = ET.fromstring(response.text)
    for element in root.iter():
        if _strip_ns(element.tag) != "row":
            continue
        row = {}
        for child in list(element):
            row[_strip_ns(child.tag).lower()] = (child.text or "").strip()
        rows.append(row)
    return rows


def _candidate_where(number):
    literal = _sql_literal(number)
    return f"n.dnorpattern LIKE '{literal}%'"


def _route_plan_sql(number, include_extended_details=True):
    detail_columns = "tpu.name AS type_name, lg.name AS line_group_name, " if include_extended_details else ""
    detail_joins = (
        "LEFT OUTER JOIN typepatternusage tpu ON tpu.enum = n.tkpatternusage "
        "LEFT OUTER JOIN linegroupnumplanmap lgnpm ON lgnpm.fknumplan = n.pkid "
        "LEFT OUTER JOIN linegroup lg ON lg.pkid = lgnpm.fklinegroup "
        if include_extended_details else ""
    )
    return (
        f"SELECT FIRST {MAX_CANDIDATE_ROWS} n.dnorpattern AS pattern, "
        "r.name AS route_partition, n.description AS description, "
        f"n.tkpatternusage AS pattern_usage, {detail_columns}"
        "n.calledpartytransformationmask AS called_party_transform_mask, "
        "n.iscallable AS is_callable, d.name AS device_name "
        "FROM numplan n "
        "LEFT OUTER JOIN routepartition r ON r.pkid = n.fkroutepartition "
        f"{detail_joins}"
        "LEFT OUTER JOIN devicenumplanmap dnm ON dnm.fknumplan = n.pkid "
        "LEFT OUTER JOIN device d ON d.pkid = dnm.fkdevice "
        f"WHERE ({_candidate_where(number)}) "
        "ORDER BY n.dnorpattern, r.name, d.name"
    )


def lookup_route_plan(cucm_host, cucm_user, cucm_pass, number):
    clean_number = _normalize_number(number)
    if not clean_number:
        raise ValueError("A phone number or dial string is required.")
    if len(clean_number) > 50:
        raise ValueError("The dial string must be 50 characters or fewer.")

    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    used_extended_details_fallback = False
    try:
        sql_rows = _execute_sql(session, cucm_host, _route_plan_sql(clean_number, include_extended_details=True))
    except Exception:
        used_extended_details_fallback = True
        sql_rows = _execute_sql(session, cucm_host, _route_plan_sql(clean_number, include_extended_details=False))

    matches = {}
    for row in sql_rows:
        pattern = row.get("pattern", "")
        match_kind = _match_kind(pattern, clean_number)
        if not match_kind:
            continue
        partition = row.get("route_partition", "") or "<None>"
        usage = row.get("pattern_usage", "")
        key = (pattern, partition, usage)
        if key not in matches:
            matches[key] = {
                "match": match_kind,
                "pattern": pattern,
                "route_partition": partition,
                "type": row.get("type_name", "") or PATTERN_USAGE_NAMES.get(usage, f"Pattern Usage {usage}"),
                "description": row.get("description", ""),
                "called_party_transform_mask": row.get("called_party_transform_mask", ""),
                "is_callable": row.get("is_callable", ""),
                "devices": [],
                "line_groups": [],
            }
        device_name = row.get("device_name", "")
        if device_name and device_name not in matches[key]["devices"]:
            matches[key]["devices"].append(device_name)
        line_group_name = row.get("line_group_name", "")
        if line_group_name and line_group_name not in matches[key]["line_groups"]:
            matches[key]["line_groups"].append(line_group_name)

    results = list(matches.values())
    results.sort(key=lambda item: (0 if item["match"] == "Exact" else 1, item["pattern"], item["route_partition"]))
    return {
        "query": clean_number,
        "results": results[:MAX_RESULTS],
        "total_matches": len(results),
        "truncated": len(results) > MAX_RESULTS,
        "extended_details_fallback": used_extended_details_fallback,
    }
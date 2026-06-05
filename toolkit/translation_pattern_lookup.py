import requests
import urllib3
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape as xml_escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
AXL_NS = "http://www.cisco.com/AXL/API/15.0"
MAX_RESULTS = 200


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _find_first_by_localname(elem, localname):
    for e in elem.iter():
        if _strip_ns(e.tag) == localname:
            return e
    return None


def _find_localname_text(elem, localnames):
    for name in localnames:
        found = _find_first_by_localname(elem, name)
        if found is not None and found.text:
            value = found.text.strip()
            if value:
                return value
    return ""


def _axl_post(session, cucm_host, soap_xml):
    url = f"https://{cucm_host}:8443/axl/"
    headers = {"Content-Type": "text/xml"}
    resp = session.post(url, data=soap_xml.encode("utf-8"), headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.text


def _soap_list_trans_pattern(pattern_query):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:listTransPattern sequence="1">
      <searchCriteria>
        <pattern>%{xml_escape(pattern_query.strip())}%</pattern>
      </searchCriteria>
      <returnedTags>
        <pattern/>
        <routePartitionName/>
        <description/>
        <calledPartyTransformationMask/>
      </returnedTags>
    </axl:listTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""


def _soap_get_trans_pattern(pattern, route_partition):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getTransPattern sequence="1">
      <pattern>{xml_escape(pattern)}</pattern>
      <routePartitionName>{xml_escape(route_partition)}</routePartitionName>
    </axl:getTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""


def _parse_trans_pattern_node(node):
    return {
        "pattern": _find_localname_text(node, ["pattern"]),
        "description": _find_localname_text(node, ["description"]),
        "called_party_transform_mask": _find_localname_text(
            node,
            [
                "calledPartyTransformationMask",
                "calledPartyTransformMask",
            ],
        ),
        "route_partition": _find_localname_text(node, ["routePartitionName"]),
    }


def lookup_translation_patterns(cucm_host, cucm_user, cucm_pass, pattern_query):
    pattern_query = (pattern_query or "").strip()
    if not pattern_query:
        raise ValueError("pattern_query is required")

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    list_xml = _axl_post(session, cucm_host, _soap_list_trans_pattern(pattern_query))
    root = ET.fromstring(list_xml)

    seeds = []
    seen_seed = set()
    for elem in root.iter():
        if _strip_ns(elem.tag) != "transPattern":
            continue
        item = _parse_trans_pattern_node(elem)
        key = (item["pattern"], item["route_partition"])
        if not item["pattern"] or key in seen_seed:
            continue
        seen_seed.add(key)
        seeds.append(item)
        if len(seeds) >= MAX_RESULTS:
            break

    if not seeds:
        return []

    results = []
    seen_result = set()
    for seed in seeds:
        pattern = seed.get("pattern", "")
        route_partition = seed.get("route_partition", "")

        detail = dict(seed)
        if pattern and route_partition:
            try:
                get_xml = _axl_post(
                    session,
                    cucm_host,
                    _soap_get_trans_pattern(pattern, route_partition),
                )
                get_root = ET.fromstring(get_xml)
                tp = _find_first_by_localname(get_root, "transPattern")
                if tp is not None:
                    detail = _parse_trans_pattern_node(tp)
            except Exception:
                detail = dict(seed)

        key = (detail.get("pattern", ""), detail.get("route_partition", ""))
        if not detail.get("pattern") or key in seen_result:
            continue
        seen_result.add(key)
        results.append(detail)

    return results

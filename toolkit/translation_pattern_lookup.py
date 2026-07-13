import csv
import io
import requests
import urllib3
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape as xml_escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
AXL_NS = "http://www.cisco.com/AXL/API/15.0"
MAX_RESULTS = 5000


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


def _normalize_text(s):
    if s is None:
        return ""
    return str(s).strip()


def _flatten_element(elem, prefix="", out=None):
    """Flatten XML to dot-notation keys for full template generation."""
    if out is None:
        out = {}

    tag = _strip_ns(elem.tag)
    key_base = f"{prefix}.{tag}" if prefix else tag

    for ak, av in elem.attrib.items():
        out[f"{key_base}.@{ak}"] = _normalize_text(av)

    children = list(elem)
    text = _normalize_text(elem.text)

    if not children:
        if text != "":
            out[key_base] = text
        return out

    if text != "":
        out[key_base] = text

    groups = {}
    for child in children:
        groups.setdefault(_strip_ns(child.tag), []).append(child)

    for child_tag, items in groups.items():
        if len(items) == 1:
            _flatten_element(items[0], key_base, out)
        else:
            for i, item in enumerate(items):
                indexed_prefix = f"{key_base}.{child_tag}[{i}]"
                for ak, av in item.attrib.items():
                    out[f"{indexed_prefix}.@{ak}"] = _normalize_text(av)

                item_text = _normalize_text(item.text)
                if item_text and not list(item):
                    out[indexed_prefix] = item_text

                for sub in list(item):
                    _flatten_element(sub, indexed_prefix, out)

    return out


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
    session.trust_env = False
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


def get_translation_pattern_full(cucm_host, cucm_user, cucm_pass, pattern, route_partition):
    pattern = (pattern or "").strip()
    route_partition = (route_partition or "").strip()
    if not pattern or not route_partition:
        raise ValueError("pattern and route_partition are required")

    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    get_xml = _axl_post(
        session,
        cucm_host,
        _soap_get_trans_pattern(pattern, route_partition),
    )
    root = ET.fromstring(get_xml)
    tp = _find_first_by_localname(root, "transPattern")
    if tp is None:
        raise RuntimeError("Could not locate transPattern node in getTransPattern response")

    detail = _parse_trans_pattern_node(tp)
    full_fields = {}
    for child in list(tp):
        _flatten_element(child, prefix="transPattern", out=full_fields)

    detail["full_fields"] = full_fields
    return detail


def build_translation_pattern_template(cucm_host, cucm_user, cucm_pass, pattern_prefix):
    pattern_prefix = (pattern_prefix or "").strip()
    if not pattern_prefix:
        raise ValueError("pattern_prefix is required")

    matches = lookup_translation_patterns(cucm_host, cucm_user, cucm_pass, pattern_prefix)
    example = None
    for item in matches:
        if (item.get("pattern") or "").startswith(pattern_prefix):
            example = item
            break

    if example is None:
        raise RuntimeError(f"No translation pattern found beginning with {pattern_prefix}")

    detail = get_translation_pattern_full(
        cucm_host,
        cucm_user,
        cucm_pass,
        example.get("pattern", ""),
        example.get("route_partition", ""),
    )

    full_fields = dict(detail.get("full_fields") or {})
    # Keep the template strict: only these two are intended to change.
    full_fields["transPattern.pattern"] = "CHANGE_ME_TRANSLATION_PATTERN"
    full_fields["transPattern.description"] = "CHANGE_ME_DESCRIPTION"
    full_fields["template.source_pattern"] = example.get("pattern", "")
    full_fields["template.source_route_partition"] = example.get("route_partition", "")

    preferred = [
        "transPattern.pattern",
        "transPattern.description",
        "template.source_pattern",
        "template.source_route_partition",
    ]
    keys = preferred + sorted(k for k in full_fields.keys() if k not in set(preferred))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(keys)
    writer.writerow([full_fields.get(k, "") for k in keys])

    filename = f"translation_pattern_template_{pattern_prefix}.csv"
    return output.getvalue().encode("utf-8"), filename, detail

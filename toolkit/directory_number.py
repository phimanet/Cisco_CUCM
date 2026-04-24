import urllib3
import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
import csv
import io
import datetime
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
AXL_NS = "http://www.cisco.com/AXL/API/15.0"
NS = {"soapenv": SOAPENV_NS, "axl": AXL_NS}


def _soap_envelope(body_xml: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAPENV_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
  <soapenv:Body>
{body_xml}
  </soapenv:Body>
</soapenv:Envelope>"""


def _normalize_text(s: str) -> str:
    if s is None:
        return ""
    return re.sub(r"\s+", " ", s).strip()


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _axl_post(session: requests.Session, cucm_host: str, soap_xml: str) -> str:
    url = f"https://{cucm_host}:8443/axl/"
    headers = {"Content-Type": "text/xml"}
    resp = session.post(url, data=soap_xml.encode("utf-8"), headers=headers, timeout=90)
    resp.raise_for_status()
    return resp.text


def _flatten_element(elem: ET.Element, prefix: str = "", out: dict = None) -> dict:
    """
    Recursively flattens XML into dot-notation.
    - Attributes become .@attr
    - Repeated sibling elements become tag[0], tag[1], ...
    """
    if out is None:
        out = {}

    tag = _strip_ns(elem.tag)
    key_base = f"{prefix}.{tag}" if prefix else tag

    # Attributes
    for ak, av in elem.attrib.items():
        out[f"{key_base}.@{ak}"] = _normalize_text(av)

    children = list(elem)
    text = _normalize_text(elem.text)

    # Leaf node
    if not children:
        if text != "":
            out[key_base] = text
        return out

    # Mixed content (rare)
    if text != "":
        out[key_base] = text

    # Group children by tag name to index repeats
    groups = {}
    for c in children:
        groups.setdefault(_strip_ns(c.tag), []).append(c)

    for child_tag, items in groups.items():
        if len(items) == 1:
            _flatten_element(items[0], key_base, out)
        else:
            for i, item in enumerate(items):
                indexed_prefix = f"{key_base}.{child_tag}[{i}]"

                # attributes/text at the repeated node
                for ak, av in item.attrib.items():
                    out[f"{indexed_prefix}.@{ak}"] = _normalize_text(av)
                item_text = _normalize_text(item.text)
                if item_text and not list(item):
                    out[indexed_prefix] = item_text

                for sub in list(item):
                    _flatten_element(sub, indexed_prefix, out)

    return out


def _soap_list_line(pattern_expr: str, route_partition: str = "") -> str:
    """
    listLine requires returnedTags (many CUCM versions will return null/empty otherwise).
    We keep it minimal and pull UUID + pattern + routePartitionName.

    Wildcards: caller can pass %, e.g. 858%, %6648, 2481003, etc.
    """
    rp_xml = ""
    if route_partition.strip():
        rp_xml = f"<routePartitionName>{route_partition.strip()}</routePartitionName>"

    body = f"""  <axl:listLine sequence="1">
    <searchCriteria>
      <pattern>{pattern_expr}</pattern>
      {rp_xml}
    </searchCriteria>
    <returnedTags>
      <uuid/>
      <pattern/>
      <routePartitionName/>
    </returnedTags>
  </axl:listLine>"""
    return _soap_envelope(body)


def _soap_get_line(uuid: str) -> str:
    """
    getLine can return a full object without returnedTags.
    """
    body = f"""  <axl:getLine sequence="1">
    <uuid>{uuid}</uuid>
  </axl:getLine>"""
    return _soap_envelope(body)


def _csv_error(filename: str, code: str, detail: str):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["error", "detail"])
    w.writerow([code, detail])
    return out.getvalue().encode("utf-8"), filename


def _extract_uuid_from_line_elem(line_elem: ET.Element) -> str:
    """
    CUCM list* responses sometimes return UUID as:
      - <uuid>...</uuid> child
      - uuid="..." attribute on the <line> element
    This function supports both.
    """
    # 1) attribute form
    for k, v in line_elem.attrib.items():
        if k.lower().endswith("uuid") and _normalize_text(v):
            return _normalize_text(v)

    # 2) child element form
    for c in list(line_elem):
        if _strip_ns(c.tag) == "uuid" and _normalize_text(c.text):
            return _normalize_text(c.text)

    return ""


def export_directory_numbers(
    cucm_host: str,
    cucm_user: str,
    cucm_pass: str,
    dn_contains: str,
    route_partition: str = ""
):
    """
    Web-enabled Directory Number export (FULL fields).

    Two-step:
      1) listLine (minimal returnedTags) to obtain UUIDs
      2) getLine (full object) per UUID, flatten everything

    Pattern behavior:
      - If user includes '%' in dn_contains, use it as-is
      - Else default to starts-with: dn_contains%
    """

    try:
        session = requests.Session()
        session.verify = False
        session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

        dn_contains = (dn_contains or "").strip()
        if not dn_contains:
            raise ValueError("dn_contains is required")

        # Allow advanced wildcard input:
        # - user types 858% (starts with 858)
        # - user types %6648 (ends with 6648)
        # - user types 2481003 (we treat as 2481003%)
        if "%" in dn_contains:
            pattern_expr = dn_contains
        else:
            pattern_expr = f"{dn_contains}%"

        # STEP 1: listLine -> UUIDs
        try:
            list_resp = _axl_post(
                session,
                cucm_host,
                _soap_list_line(pattern_expr, route_partition)
            )
        except requests.exceptions.HTTPError as e:
            return _csv_error("axl_error.csv", "AXL_LISTLINE_HTTP_ERROR", str(e))
        except Exception as e:
            return _csv_error("axl_error.csv", "AXL_LISTLINE_EXCEPTION", str(e))

        try:
            root = ET.fromstring(list_resp)
        except Exception as e:
            return _csv_error("axl_error.csv", "LISTLINE_XML_PARSE_ERROR", str(e))

        body = root.find("soapenv:Body", NS)
        if body is None:
            return _csv_error("axl_error.csv", "LISTLINE_SOAP_BODY_MISSING", "SOAP Body not found in listLine response")

        line_nodes = [e for e in body.iter() if _strip_ns(e.tag) == "line"]

        uuids = []
        for ln in line_nodes:
            u = _extract_uuid_from_line_elem(ln)
            if u:
                uuids.append(u)

        # De-dupe while preserving order
        seen = set()
        uuids = [u for u in uuids if not (u in seen or seen.add(u))]

        # If CUCM returned <line> nodes but no UUIDs, report parsing issue (not NO_RESULTS)
        if line_nodes and not uuids:
            sample = ET.tostring(line_nodes[0], encoding="unicode")[:500]
            return _csv_error(
                "axl_error.csv",
                "LISTLINE_UUID_PARSE_FAILED",
                f"Found line elements but could not extract UUID (child or attribute). sample={sample}"
            )

        if not uuids:
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(["status", "detail"])
            w.writerow(["NO_RESULTS", f"pattern={pattern_expr} route_partition={route_partition.strip()}"])
            return out.getvalue().encode("utf-8"), "directory_numbers_empty.csv"

        # STEP 2: getLine per UUID -> flatten full object
        rows = []
        all_keys = set()

        for uuid in uuids:
            try:
                get_resp = _axl_post(session, cucm_host, _soap_get_line(uuid))
            except Exception as e:
                err = {
                    "line.uuid": uuid,
                    "error_type": "GETLINE_HTTP_OR_NETWORK_FAILED",
                    "error_detail": str(e)
                }
                rows.append(err)
                all_keys.update(err.keys())
                continue

            try:
                get_root = ET.fromstring(get_resp)
            except Exception as e:
                err = {
                    "line.uuid": uuid,
                    "error_type": "GETLINE_XML_PARSE_FAILED",
                    "error_detail": str(e)
                }
                rows.append(err)
                all_keys.update(err.keys())
                continue

            get_body = get_root.find("soapenv:Body", NS)
            if get_body is None:
                err = {
                    "line.uuid": uuid,
                    "error_type": "GETLINE_SOAP_BODY_MISSING",
                    "error_detail": "SOAP Body not found in getLine response"
                }
                rows.append(err)
                all_keys.update(err.keys())
                continue

            # Find <line> element defensively
            line_node = None
            for e in get_body.iter():
                if _strip_ns(e.tag) == "line":
                    line_node = e
                    break

            if line_node is None:
                err = {
                    "line.uuid": uuid,
                    "error_type": "GETLINE_NO_LINE_ELEMENT",
                    "error_detail": "No <line> element returned by getLine"
                }
                rows.append(err)
                all_keys.update(err.keys())
                continue

            try:
                flat = {}
                for child in list(line_node):
                    _flatten_element(child, prefix="line", out=flat)

                flat["line.uuid"] = uuid
                rows.append(flat)
                all_keys.update(flat.keys())
            except Exception as e:
                err = {
                    "line.uuid": uuid,
                    "error_type": "DN_FLATTEN_FAILED",
                    "error_detail": str(e)
                }
                rows.append(err)
                all_keys.update(err.keys())

        headers = sorted(all_keys)
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = dn_contains.replace(" ", "_")
        filename = f"directory_numbers_full_{safe}_{ts}.csv"
        return out.getvalue().encode("utf-8"), filename

    except Exception as e:
        # Final catch-all: never crash FastAPI; return error CSV
        return _csv_error("axl_error.csv", "EXPORT_DN_FATAL", str(e))

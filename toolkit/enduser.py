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


def _axl_post(session: requests.Session, cucm_host: str, soap_xml: str) -> str:
    url = f"https://{cucm_host}:8443/axl/"
    headers = {"Content-Type": "text/xml"}
    resp = session.post(url, data=soap_xml.encode("utf-8"), headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.text


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _normalize_text(s: str) -> str:
    if s is None:
        return ""
    return re.sub(r"\s+", " ", s).strip()


def _find_first_by_localname(elem: ET.Element, localname: str):
    for e in elem.iter():
        if _strip_ns(e.tag) == localname:
            return e
    return None


def _flatten_element(elem: ET.Element, prefix: str = "", out: dict = None) -> dict:
    """
    Flattens XML to dot-notation keys.
    Repeated siblings are indexed: tag[0], tag[1], ...
    Attributes stored as .@attr.
    """
    if out is None:
        out = {}

    tag = _strip_ns(elem.tag)
    key_base = f"{prefix}.{tag}" if prefix else tag

    # attributes
    for ak, av in elem.attrib.items():
        out[f"{key_base}.@{ak}"] = _normalize_text(av)

    children = list(elem)
    text = _normalize_text(elem.text)

    # leaf node
    if not children:
        if text != "":
            out[key_base] = text
        return out

    # mixed content (rare)
    if text != "":
        out[key_base] = text

    # group children by local tag name
    groups = {}
    for c in children:
        groups.setdefault(_strip_ns(c.tag), []).append(c)

    for child_tag, items in groups.items():
        if len(items) == 1:
            _flatten_element(items[0], key_base, out)
        else:
            for i, item in enumerate(items):
                indexed_prefix = f"{key_base}.{child_tag}[{i}]"

                # attributes/text at this repeated node
                for ak, av in item.attrib.items():
                    out[f"{indexed_prefix}.@{ak}"] = _normalize_text(av)

                item_text = _normalize_text(item.text)
                if item_text and not list(item):
                    out[indexed_prefix] = item_text

                # flatten descendants beneath the repeated node
                for sub in list(item):
                    _flatten_element(sub, indexed_prefix, out)

    return out


def _soap_list_user(lastname_like: str) -> str:
    body = f"""  <axl:listUser sequence="1">
    <searchCriteria>
      <lastName>{lastname_like}</lastName>
    </searchCriteria>
    <returnedTags>
      <userid/>
      <firstName/>
      <lastName/>
    </returnedTags>
  </axl:listUser>"""
    return _soap_envelope(body)


def _soap_get_user(userid: str) -> str:
    # Intentionally no returnedTags so CUCM returns default set for getUser
    body = f"""  <axl:getUser sequence="1">
    <userid>{userid}</userid>
  </axl:getUser>"""
    return _soap_envelope(body)


def export_endusers_all_fields(cucm_host: str, cucm_user: str, cucm_pass: str, lastname: str):
    """
    Web-enabled End User export:
    listUser by lastName LIKE %lastname% -> getUser (no returnedTags) -> flatten -> CSV bytes
    Returns (csv_bytes, filename)
    """
    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    lastname = (lastname or "").strip()
    if lastname == "":
        raise ValueError("lastname is required")

    lastname_like = f"%{lastname}%"

    rows = []
    all_keys = set()

    # 1) listUser (graceful error CSV on failures)
    list_xml = _soap_list_user(lastname_like)
    try:
        list_resp = _axl_post(session, cucm_host, list_xml)
    except requests.exceptions.HTTPError as e:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["error", "detail"])
        writer.writerow(["AXL_HTTP_ERROR", str(e)])
        return output.getvalue().encode("utf-8"), "axl_error.csv"
    except Exception as e:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["error", "detail"])
        writer.writerow(["AXL_EXCEPTION", str(e)])
        return output.getvalue().encode("utf-8"), "axl_error.csv"

    # parse listUser response
    root = ET.fromstring(list_resp)
    body = root.find("soapenv:Body", NS)
    if body is None:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["error", "detail"])
        writer.writerow(["SOAP_PARSE_ERROR", "SOAP Body not found in listUser response"])
        return output.getvalue().encode("utf-8"), "axl_error.csv"

    user_elems = [e for e in body.iter() if _strip_ns(e.tag) == "user"]

    userids = []
    for u in user_elems:
        uid_elem = _find_first_by_localname(u, "userid")
        uid = _normalize_text(uid_elem.text) if uid_elem is not None else ""
        if uid:
            userids.append(uid)

    # de-dupe while preserving order
    seen = set()
    userids = [u for u in userids if not (u in seen or seen.add(u))]

    if not userids:
        rows = [{"status": "NO_RESULTS", "lastname_like": lastname_like, "cucm_host": cucm_host}]
        all_keys = set(rows[0].keys())
    else:
        # 2) getUser for each userid
        for uid in userids:
            try:
                get_xml = _soap_get_user(uid)
                get_resp = _axl_post(session, cucm_host, get_xml)

                get_root = ET.fromstring(get_resp)
                get_body = get_root.find("soapenv:Body", NS)
                if get_body is None:
                    raise RuntimeError("SOAP Body not found in getUser response")

                user_node = _find_first_by_localname(get_body, "user")
                if user_node is None:
                    raise RuntimeError("No <user> node returned")

                flat = {}
                for child in list(user_node):
                    _flatten_element(child, prefix="user", out=flat)

                flat["user.userid"] = uid
                rows.append(flat)
                all_keys.update(flat.keys())

            except Exception as e:
                err_row = {
                    "user.userid": uid,
                    "error_type": "GET_USER_FAILED",
                    "error_detail": str(e)
                }
                rows.append(err_row)
                all_keys.update(err_row.keys())

    # 3) write CSV to memory
    headers = sorted(all_keys)
    output = io.StringIO()
    w = csv.DictWriter(output, fieldnames=headers)
    w.writeheader()
    for r in rows:
        w.writerow(r)

    csv_bytes = output.getvalue().encode("utf-8")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"enduser_export_{lastname}_{ts}.csv".replace(" ", "_")
    return csv_bytes, filename


import csv
import datetime
import io
import re
import requests
import urllib3
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _axl_post(session, cucm_host, soap_xml):
    url = f"https://{cucm_host}:8443/axl/"
    headers = {"Content-Type": "text/xml"}
    return session.post(
        url,
        data=soap_xml.encode("utf-8"),
        headers=headers,
        timeout=120,
        verify=False,
    )


def _strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _find_child(elem, tag_name):
    for child in list(elem):
        if _strip_ns(child.tag) == tag_name:
            return child
    return None


def _find_first_text(elem, path_candidates):
    for path in path_candidates:
        cur = elem
        found = True
        for tag_name in path:
            cur = _find_child(cur, tag_name)
            if cur is None:
                found = False
                break
        if found and cur is not None and cur.text:
            value = cur.text.strip()
            if value:
                return value
    return ""


def _soap_get_line_group(line_group_name):
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:getLineGroup>
         <name>{escape(line_group_name)}</name>
      </axl:getLineGroup>
   </soapenv:Body>
</soapenv:Envelope>"""


def _soap_list_line_groups(search_text):
     search_name = f"%{search_text}%" if search_text else "%"
     return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
    <soapenv:Body>
        <axl:listLineGroup>
            <searchCriteria>
                <name>{escape(search_name)}</name>
            </searchCriteria>
            <returnedTags>
                <name/>
            </returnedTags>
        </axl:listLineGroup>
    </soapenv:Body>
</soapenv:Envelope>"""


def _normalize_partial_text(value):
    text = str(value or "").lower()
    return re.sub(r"[^a-z0-9]", "", text)


def _filter_names_by_partial_query(names, search_text):
    query = str(search_text or "").strip()
    if not query:
        return sorted(set(names))

    lowered_query = query.lower()
    normalized_query = _normalize_partial_text(query)
    query_tokens = [tok for tok in re.split(r"[^a-z0-9]+", lowered_query) if tok]

    matched = []
    for name in sorted(set(names)):
        lowered_name = str(name or "").lower()
        normalized_name = _normalize_partial_text(lowered_name)

        # Direct partial match first.
        if lowered_query in lowered_name:
            matched.append(name)
            continue

        # Ignore separators for partial matching (space, underscore, hyphen, etc.).
        if normalized_query and normalized_query in normalized_name:
            matched.append(name)
            continue

        # Multi-token partial support: all tokens must appear somewhere in the name.
        if query_tokens and all(tok in lowered_name or tok in normalized_name for tok in query_tokens):
            matched.append(name)

    return matched


def _soap_update_line_group_members(line_group_name, members):
    member_xml = []
    for idx, member in enumerate(members, start=1):
        pattern = member.get("pattern", "").strip()
        partition = member.get("routePartitionName", "").strip()
        if not pattern or not partition:
            continue

        line_selection_order = str(member.get("lineSelectionOrder", "")).strip()
        if not line_selection_order:
            line_selection_order = str(idx)

        member_xml.append(
            "            <member>\n"
            "              <directoryNumber>\n"
            f"                <pattern>{escape(pattern)}</pattern>\n"
            f"                <routePartitionName>{escape(partition)}</routePartitionName>\n"
            "              </directoryNumber>\n"
            f"              <lineSelectionOrder>{escape(line_selection_order)}</lineSelectionOrder>\n"
            "            </member>"
        )

    members_xml = "\n".join(member_xml)
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:updateLineGroup>
         <name>{escape(line_group_name)}</name>
         <members>
{members_xml}
         </members>
      </axl:updateLineGroup>
   </soapenv:Body>
</soapenv:Envelope>"""


def _extract_line_group_members(root):
    members = []
    for member in root.iter():
        if _strip_ns(member.tag) != "member":
            continue

        pattern = _find_first_text(member, [["directoryNumber", "pattern"], ["pattern"]])
        partition = _find_first_text(
            member,
            [["directoryNumber", "routePartitionName"], ["routePartitionName"]],
        )
        line_selection_order = _find_first_text(member, [["lineSelectionOrder"]])
        if pattern and partition:
            members.append({
                "pattern": pattern,
                "routePartitionName": partition,
                "lineSelectionOrder": line_selection_order,
            })
    return members


def search_line_groups(cucm_host, cucm_user, cucm_pass, search_text):
    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    response = _axl_post(session, cucm_host, _soap_list_line_groups((search_text or "").strip()))
    if response.status_code != 200:
        raise RuntimeError(f"listLineGroup failed with HTTP {response.status_code}: {response.text[:1200]}")

    root = ET.fromstring(response.text)
    names = []
    for elem in root.iter():
        if _strip_ns(elem.tag) != "lineGroup":
            continue
        name = _find_first_text(elem, [["name"]])
        if name:
            names.append(name)

    direct_names = sorted(set(names))
    if direct_names:
        return direct_names

    # Fallback: if filtered query found nothing, get full list and apply local fuzzy filter.
    # This handles CUCM-side search edge cases where wildcard matching is too strict.
    if str(search_text or "").strip():
        full_response = _axl_post(session, cucm_host, _soap_list_line_groups(""))
        if full_response.status_code == 200:
            full_root = ET.fromstring(full_response.text)
            full_names = []
            for elem in full_root.iter():
                if _strip_ns(elem.tag) != "lineGroup":
                    continue
                name = _find_first_text(elem, [["name"]])
                if name:
                    full_names.append(name)
            return _filter_names_by_partial_query(full_names, search_text)

    return direct_names


def get_line_group_members(cucm_host, cucm_user, cucm_pass, line_group_name):
    """Return current members for a single Line Group as pattern/partition/order rows."""
    clean_group = (line_group_name or "").strip()
    if not clean_group:
        raise RuntimeError("Line Group Name is required")

    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    response = _axl_post(session, cucm_host, _soap_get_line_group(clean_group))
    if response.status_code != 200:
        raise RuntimeError(f"getLineGroup failed with HTTP {response.status_code}: {response.text[:1200]}")

    root = ET.fromstring(response.text)
    return _extract_line_group_members(root)


def edit_line_group_members(cucm_host, cucm_user, cucm_pass, line_group_name, action, dn_pattern, dn_partition):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_group = (line_group_name or "").strip().replace(" ", "_") or "line_group"
    filename = f"edit_line_group_members_{safe_group}_{ts}.csv"

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])

    clean_group = (line_group_name or "").strip()
    clean_action = (action or "").strip().lower()
    clean_dn = (dn_pattern or "").strip()
    clean_partition = (dn_partition or "").strip() or "ENT_DEVICE_PT"

    if not clean_group:
        writer.writerow(["Validation", "Failed", "Line Group Name is required"])
        return out.getvalue().encode("utf-8"), filename

    if clean_action not in {"add", "remove"}:
        writer.writerow(["Validation", "Failed", "Action must be add or remove"])
        return out.getvalue().encode("utf-8"), filename

    if not clean_dn:
        writer.writerow(["Validation", "Failed", "Directory Number Pattern is required"])
        return out.getvalue().encode("utf-8"), filename

    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    try:
        get_resp = _axl_post(session, cucm_host, _soap_get_line_group(clean_group))
        if get_resp.status_code != 200:
            writer.writerow([
                "Get Line Group",
                "Failed",
                f"HTTP {get_resp.status_code}: {get_resp.text[:1200]}",
            ])
            return out.getvalue().encode("utf-8"), filename

        root = ET.fromstring(get_resp.text)
        members = _extract_line_group_members(root)
        writer.writerow([
            "Get Line Group",
            "Success",
            f"Loaded {len(members)} current member(s)",
        ])

        target = {
            "pattern": clean_dn,
            "routePartitionName": clean_partition,
        }
        exists = any(
            m.get("pattern") == target["pattern"] and m.get("routePartitionName") == target["routePartitionName"]
            for m in members
        )

        if clean_action == "add":
            if exists:
                writer.writerow([
                    "Modify Members",
                    "Skipped",
                    f"{clean_dn}/{clean_partition} already exists in {clean_group}",
                ])
            else:
                members.append(target)
                # Keep lineSelectionOrder contiguous and deterministic after add.
                for index, row in enumerate(members, start=1):
                    row["lineSelectionOrder"] = str(index)
                writer.writerow([
                    "Modify Members",
                    "Success",
                    f"Prepared add for {clean_dn}/{clean_partition}",
                ])
        else:
            if not exists:
                writer.writerow([
                    "Modify Members",
                    "Skipped",
                    f"{clean_dn}/{clean_partition} was not found in {clean_group}",
                ])
            else:
                members = [
                    m
                    for m in members
                    if not (
                        m.get("pattern") == target["pattern"]
                        and m.get("routePartitionName") == target["routePartitionName"]
                    )
                ]
                # Re-index ordering after remove to avoid null/duplicate orders.
                for index, row in enumerate(members, start=1):
                    row["lineSelectionOrder"] = str(index)
                writer.writerow([
                    "Modify Members",
                    "Success",
                    f"Prepared remove for {clean_dn}/{clean_partition}",
                ])

        update_resp = _axl_post(
            session,
            cucm_host,
            _soap_update_line_group_members(clean_group, members),
        )
        if update_resp.status_code != 200:
            writer.writerow([
                "Update Line Group",
                "Failed",
                f"HTTP {update_resp.status_code}: {update_resp.text[:1200]}",
            ])
            return out.getvalue().encode("utf-8"), filename

        writer.writerow([
            "Update Line Group",
            "Success",
            f"{clean_group} now has {len(members)} member(s)",
        ])

    except Exception as exc:
        writer.writerow(["Script", "Error", str(exc)])

    return out.getvalue().encode("utf-8"), filename

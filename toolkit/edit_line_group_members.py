import csv
import datetime
import io
import requests
import urllib3
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _axl_post(session, cucm_host, soap_xml):
    url = f"https://{cucm_host}:8443/axl/"
    headers = {"Content-Type": "text/xml"}
    return session.post(url, data=soap_xml.encode("utf-8"), headers=headers, timeout=120)


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


def _soap_update_line_group_members(line_group_name, members):
    member_xml = []
    for member in members:
        pattern = member.get("pattern", "").strip()
        partition = member.get("routePartitionName", "").strip()
        if not pattern or not partition:
            continue
        member_xml.append(
            "            <member>\n"
            "              <directoryNumber>\n"
            f"                <pattern>{escape(pattern)}</pattern>\n"
            f"                <routePartitionName>{escape(partition)}</routePartitionName>\n"
            "              </directoryNumber>\n"
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
        if pattern and partition:
            members.append({
                "pattern": pattern,
                "routePartitionName": partition,
            })
    return members


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

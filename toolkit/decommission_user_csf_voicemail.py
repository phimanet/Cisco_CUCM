import csv
import datetime
import io
import urllib3
import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LAB_CUCM_IP = "lascucmpl01.ahs.int"
PROD_CUCM_IP = "lascucmpp01.ahs.int"
UNITY_LAB_SERVER = "LASCUTYPL01.ahs.int"
UNITY_PROD_SERVER = "SANCUTYP01.ahs.int"
DEFAULT_ROUTE_PARTITION = "ENT_DEVICE_PT"


def _axl_post(session, cucm_ip, soap_xml):
    url = f"https://{cucm_ip}:8443/axl/"
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


def _make_unity_url(server, path):
    server = server.strip()
    if server.startswith("http://") or server.startswith("https://"):
        base = server.rstrip("/")
    else:
        base = f"https://{server}"
    return f"{base}{path}"


def _unity_headers():
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _parse_unity_error_text(response):
    text = (response.text or "").strip()
    if not text:
        return f"HTTP {response.status_code} with empty response body"
    return f"HTTP {response.status_code}: {text[:1200]}"


def _get_user_details(session, cucm_ip, username):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Header/>
   <soapenv:Body>
      <axl:getUser>
         <userid>{escape(username)}</userid>
      </axl:getUser>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_ip, soap)
    if response.status_code != 200:
        raise RuntimeError(f"getUser failed with HTTP {response.status_code}: {response.text[:1000]}")

    root = ET.fromstring(response.text)
    user_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "user":
            user_node = elem
            break

    if user_node is None:
        raise RuntimeError("Could not locate user node in getUser response.")

    associated_devices = []
    assoc_parent = _find_child(user_node, "associatedDevices")
    if assoc_parent is not None:
        for child in list(assoc_parent):
            if _strip_ns(child.tag) == "device" and child.text and child.text.strip():
                associated_devices.append(child.text.strip())

    primary_pattern = _find_first_text(user_node, [["primaryExtension", "pattern"]])
    primary_partition = _find_first_text(user_node, [["primaryExtension", "routePartitionName"]])

    return {
        "userid": _find_first_text(user_node, [["userid"]]),
        "firstName": _find_first_text(user_node, [["firstName"]]),
        "lastName": _find_first_text(user_node, [["lastName"]]),
        "displayName": _find_first_text(user_node, [["displayName"]]),
        "associatedDevices": associated_devices,
        "primaryExtension": {
            "pattern": primary_pattern,
            "routePartitionName": primary_partition,
        },
    }


def _get_phone_details(session, cucm_ip, phone_name):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:getPhone>
         <name>{escape(phone_name)}</name>
      </axl:getPhone>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_ip, soap)
    if response.status_code != 200:
        raise RuntimeError(f"getPhone failed for {phone_name} with HTTP {response.status_code}: {response.text[:1000]}")

    root = ET.fromstring(response.text)
    phone_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "phone":
            phone_node = elem
            break

    if phone_node is None:
        raise RuntimeError(f"Could not locate phone node for {phone_name}.")

    line_entries = []
    lines_parent = _find_child(phone_node, "lines")
    if lines_parent is not None:
        for line in list(lines_parent):
            if _strip_ns(line.tag) != "line":
                continue
            pattern = _find_first_text(line, [["dirn", "pattern"]])
            partition = _find_first_text(line, [["dirn", "routePartitionName"]])
            if pattern:
                line_entries.append({
                    "pattern": pattern,
                    "partition": partition,
                })

    return {
        "name": phone_name,
        "description": _find_first_text(phone_node, [["description"]]),
        "lines": line_entries,
    }


def _build_update_user_devices_soap(
    userid,
    associated_devices,
    removed_phone,
    removed_dn,
    removed_partition,
    removed_line_description,
    clear_service_profile=True,
    clear_associated_groups=True,
):
    device_xml = "\n".join(
        f"            <device>{escape(device)}</device>" for device in associated_devices
    )

    presence_remove_xml = ""
    if removed_phone and removed_dn and removed_partition:
        presence_remove_xml = (
            "         <lineAppearanceAssociationForPresences>\n"
            "            <lineAppearanceAssociationForPresence>\n"
            "               <laapAssociate>f</laapAssociate>\n"
            "               <laapProductType>Cisco Unified Client Services Framework</laapProductType>\n"
            f"               <laapDeviceName>{escape(removed_phone)}</laapDeviceName>\n"
            f"               <laapDirectory>{escape(removed_dn)}</laapDirectory>\n"
            f"               <laapPartition>{escape(removed_partition)}</laapPartition>\n"
            f"               <laapDescription>{escape(removed_line_description)}</laapDescription>\n"
            "            </lineAppearanceAssociationForPresence>\n"
            "         </lineAppearanceAssociationForPresences>\n"
        )

    clear_fields_xml = ""
    clear_fields_xml += "            <selfService></selfService>\n"
    clear_fields_xml += "            <homeCluster>f</homeCluster>\n"
    if clear_service_profile:
        clear_fields_xml += "            <serviceProfile></serviceProfile>\n"
    clear_fields_xml += "            <primaryExtension/>\n"
    if clear_associated_groups:
        clear_fields_xml += "            <associatedGroups/>\n"

    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
    <soapenv:Body>
        <axl:updateUser>
            <userid>{escape(userid)}</userid>
            <associatedDevices>
{device_xml}
            </associatedDevices>
{clear_fields_xml}
{presence_remove_xml}      </axl:updateUser>
    </soapenv:Body>
</soapenv:Envelope>"""


def _build_update_line_inactive_soap(pattern, route_partition):
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
    <soapenv:Body>
        <axl:updateLine>
            <pattern>{escape(pattern)}</pattern>
            <routePartitionName>{escape(route_partition)}</routePartitionName>
            <alertingName></alertingName>
            <asciiAlertingName></asciiAlertingName>
            <active>false</active>
        </axl:updateLine>
    </soapenv:Body>
</soapenv:Envelope>"""


def _build_delete_phone_soap(phone_name):
    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:removePhone>
         <name>{escape(phone_name)}</name>
      </axl:removePhone>
   </soapenv:Body>
</soapenv:Envelope>"""


def _get_line_state(session, cucm_ip, pattern, route_partition):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:getLine>
         <pattern>{escape(pattern)}</pattern>
         <routePartitionName>{escape(route_partition)}</routePartitionName>
         <returnedTags>
            <active/>
            <description/>
            <associatedDevices>
               <device/>
            </associatedDevices>
         </returnedTags>
      </axl:getLine>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_ip, soap)
    if response.status_code != 200:
        return {
            "found": False,
            "active": "",
            "description": "",
            "associatedDevices": [],
        }

    root = ET.fromstring(response.text)
    line_node = None
    for elem in root.iter():
        if _strip_ns(elem.tag) == "line":
            line_node = elem
            break

    if line_node is None:
        return {
            "found": False,
            "active": "",
            "description": "",
            "associatedDevices": [],
        }

    assoc_devices = []
    assoc_parent = _find_child(line_node, "associatedDevices")
    if assoc_parent is not None:
        for child in list(assoc_parent):
            if _strip_ns(child.tag) == "device" and child.text and child.text.strip():
                assoc_devices.append(child.text.strip())

    return {
        "found": True,
        "active": _find_first_text(line_node, [["active"]]),
        "description": _find_first_text(line_node, [["description"]]),
        "associatedDevices": assoc_devices,
    }


def _get_unity_user_by_alias(session, unity_server, alias):
    query = f"(Alias is {alias})"
    url = _make_unity_url(unity_server, "/vmrest/users")
    response = session.get(url, headers=_unity_headers(), params={"query": query}, timeout=120)

    if response.status_code != 200:
        raise RuntimeError(f"Unity user lookup failed: {_parse_unity_error_text(response)}")

    if not response.text:
        return None

    try:
        data = response.json()
    except ValueError:
        return None

    users = data.get("User")
    if isinstance(users, dict):
        users = [users]
    if not isinstance(users, list):
        return None

    for user in users:
        if str(user.get("Alias", "")).lower() == alias.lower():
            return user

    return None


def _delete_unity_user_by_object_id(session, unity_server, object_id):
    url = _make_unity_url(unity_server, f"/vmrest/users/{object_id}")
    response = session.delete(url, headers=_unity_headers(), timeout=120)
    if response.status_code not in {200, 202, 204}:
        raise RuntimeError(f"Unity mailbox delete failed: {_parse_unity_error_text(response)}")


def _pick_phone_to_remove(user_details, phone_candidates):
    if len(phone_candidates) == 1:
        return phone_candidates[0]

    primary = user_details.get("primaryExtension", {})
    primary_pattern = (primary.get("pattern") or "").strip()
    primary_partition = (primary.get("routePartitionName") or "").strip()
    if primary_pattern:
        for candidate in phone_candidates:
            for line in candidate.get("all_lines", []):
                line_pattern = (line.get("pattern") or "").strip()
                line_partition = (line.get("partition") or "").strip() or DEFAULT_ROUTE_PARTITION
                if line_pattern == primary_pattern and line_partition == (primary_partition or line_partition):
                    return candidate

    return sorted(phone_candidates, key=lambda item: item.get("name", ""))[0]


def _write_error_csv(message):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])
    writer.writerow(["Script", "Error", message])
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return out.getvalue().encode("utf-8"), f"decommission_user_csf_error_{ts}.csv"


def decommission_user_csf_voicemail(
    cucm_host,
    cucm_user,
    cucm_pass,
    target_user,
):
    if not target_user or not target_user.strip():
        return _write_error_csv("target_user is required")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"decommission_user_csf_{target_user.strip()}_{ts}.csv"

    out = io.StringIO()
    log_writer = csv.writer(out)
    log_writer.writerow(["Step", "Status", "Details"])

    unity_server = UNITY_PROD_SERVER if (cucm_host or "").strip().lower() == PROD_CUCM_IP else UNITY_LAB_SERVER

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    unity_session = requests.Session()
    unity_session.verify = False
    unity_session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    try:
        user_details = _get_user_details(session, cucm_host, target_user.strip())
        display_name = " ".join(
            p for p in [user_details.get("firstName", ""), user_details.get("lastName", "")] if p
        ).strip() or user_details.get("displayName", "") or target_user.strip()

        log_writer.writerow(["Lookup User", "Success", f"Found {target_user.strip()} ({display_name})"])
        log_writer.writerow(["Environment", "Info", f"CUCM={cucm_host}; Unity={unity_server}"])

        csf_device_names = [
            d for d in user_details.get("associatedDevices", []) if d.upper().startswith("CSF")
        ]

        if not csf_device_names:
            log_writer.writerow(["Find CSF Device", "Failed", "No CSF devices associated to user"])
            return out.getvalue().encode("utf-8"), filename

        phone_candidates = []
        for device_name in csf_device_names:
            try:
                details = _get_phone_details(session, cucm_host, device_name)
            except Exception as phone_err:
                log_writer.writerow(["Get Phone", "Failed", f"{device_name}: {phone_err}"])
                continue

            primary_line = details["lines"][0] if details["lines"] else {
                "pattern": "",
                "partition": DEFAULT_ROUTE_PARTITION,
            }
            phone_candidates.append(
                {
                    "name": details["name"],
                    "description": details.get("description", ""),
                    "primary_line": primary_line,
                    "all_lines": details["lines"],
                }
            )

        if not phone_candidates:
            log_writer.writerow(["Get Phone", "Failed", "Could not fetch any CSF phone details"])
            return out.getvalue().encode("utf-8"), filename

        selected_phone = _pick_phone_to_remove(user_details, phone_candidates)
        dn_pattern = selected_phone["primary_line"].get("pattern", "").strip()
        dn_partition = selected_phone["primary_line"].get("partition", "").strip() or DEFAULT_ROUTE_PARTITION

        log_writer.writerow([
            "Select Phone",
            "Success",
            f"Selected {selected_phone['name']} with DN {dn_pattern or '<none>'}/{dn_partition}",
        ])

        updated_devices = [d for d in user_details.get("associatedDevices", []) if d != selected_phone["name"]]
        removed_line_description = selected_phone.get("description", "").strip() or f"CSF {display_name}"

        update_user_soap = _build_update_user_devices_soap(
            user_details["userid"],
            updated_devices,
            selected_phone["name"],
            dn_pattern,
            dn_partition,
            removed_line_description,
        )
        user_update_resp = _axl_post(session, cucm_host, update_user_soap)
        if user_update_resp.status_code != 200 and "Item not valid: The specified" in (user_update_resp.text or ""):
            retry_user_soap = _build_update_user_devices_soap(
                user_details["userid"],
                updated_devices,
                selected_phone["name"],
                dn_pattern,
                dn_partition,
                removed_line_description,
                clear_service_profile=False,
                clear_associated_groups=False,
            )
            retry_user_resp = _axl_post(session, cucm_host, retry_user_soap)
            if retry_user_resp.status_code == 200:
                user_update_resp = retry_user_resp
                log_writer.writerow([
                    "Update User",
                    "Info",
                    "Retried updateUser without serviceProfile/associatedGroups clear due to CUCM validation fault",
                ])

        if user_update_resp.status_code == 200:
            log_writer.writerow([
                "Update User",
                "Success",
                (
                    f"Removed device {selected_phone['name']}, cleared Primary Extension, and removed CSF line presence mapping "
                    f"for {user_details['userid']}"
                ),
            ])
        else:
            log_writer.writerow([
                "Update User",
                "Failed",
                f"HTTP {user_update_resp.status_code}: {user_update_resp.text[:1000]}",
            ])

        delete_phone_soap = _build_delete_phone_soap(selected_phone["name"])
        delete_phone_resp = _axl_post(session, cucm_host, delete_phone_soap)
        if delete_phone_resp.status_code == 200:
            log_writer.writerow(["Remove Phone", "Success", f"Removed phone {selected_phone['name']}"])
        else:
            log_writer.writerow([
                "Remove Phone",
                "Failed",
                f"HTTP {delete_phone_resp.status_code}: {delete_phone_resp.text[:1000]}",
            ])

        try:
            unity_user = _get_unity_user_by_alias(unity_session, unity_server, user_details["userid"])
            if unity_user and unity_user.get("ObjectId"):
                _delete_unity_user_by_object_id(unity_session, unity_server, unity_user["ObjectId"])
                log_writer.writerow([
                    "Delete Unity Mailbox",
                    "Success",
                    f"Deleted Unity mailbox alias {user_details['userid']} on {unity_server}",
                ])
            else:
                log_writer.writerow([
                    "Delete Unity Mailbox",
                    "Skipped",
                    f"No Unity mailbox found for alias {user_details['userid']}",
                ])
        except Exception as unity_err:
            log_writer.writerow(["Delete Unity Mailbox", "Failed", str(unity_err)])

        if dn_pattern:
            update_line_soap = _build_update_line_inactive_soap(dn_pattern, dn_partition)
            line_resp = _axl_post(session, cucm_host, update_line_soap)

            if line_resp.status_code == 200:
                log_writer.writerow([
                    "Update Line Inactive",
                    "Success",
                    f"Marked {dn_pattern}/{dn_partition} inactive and reusable",
                ])
            else:
                log_writer.writerow([
                    "Update Line Inactive",
                    "Failed",
                    f"HTTP {line_resp.status_code}: {line_resp.text[:1000]}",
                ])

            line_state = _get_line_state(session, cucm_host, dn_pattern, dn_partition)
            if line_state["found"]:
                summary = (
                    f"active={line_state['active']}; associatedDevices={len(line_state['associatedDevices'])}; "
                    f"description={line_state['description']}"
                )
                log_writer.writerow(["Verify Line", "Success", summary])
            else:
                log_writer.writerow(["Verify Line", "Failed", "Could not read line state after update"])
        else:
            log_writer.writerow(["Update Line Inactive", "Skipped", "No DN found on selected phone"])

    except Exception as e:
        log_writer.writerow(["Script", "Error", str(e)])

    return out.getvalue().encode("utf-8"), filename

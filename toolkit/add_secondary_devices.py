import csv
import datetime
import io
import json
import os
import urllib3
import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_ROUTE_PARTITION = "ENT_DEVICE_PT"
TCT_TEMPLATE_FILE = "phone_device_template_tct.json"
BOT_TEMPLATE_FILE = "phone_device_template_bot.json"


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


def _load_template(template_file):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(base_dir, template_file)
    if not os.path.exists(template_path):
        raise RuntimeError(f"Template file not found: {template_path}")

    with open(template_path, "r", encoding="utf-8") as template_handle:
        return json.load(template_handle)


def _get_user_details(session, cucm_host, username):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Header/>
   <soapenv:Body>
      <axl:getUser>
         <userid>{escape(username)}</userid>
      </axl:getUser>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
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


def _phone_exists(session, cucm_host, phone_name):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:getPhone>
         <name>{escape(phone_name)}</name>
      </axl:getPhone>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
    return response.status_code == 200


def _build_add_phone_soap(user_details, new_phone_name, dn_pattern, dn_partition, template, description_prefix):
    optional_fields = []
    for tag_name, key_name in [
        ("callingSearchSpaceName", "callingSearchSpaceName"),
        ("devicePoolName", "devicePoolName"),
        ("commonPhoneConfigName", "commonPhoneConfigName"),
        ("locationName", "locationName"),
        ("mediaResourceListName", "mediaResourceListName"),
        ("presenceGroupName", "presenceGroupName"),
        ("subscribeCallingSearchSpaceName", "subscribeCallingSearchSpaceName"),
        ("rerouteCallingSearchSpaceName", "rerouteCallingSearchSpaceName"),
        ("sipProfileName", "sipProfileName"),
        ("softkeyTemplateName", "softkeyTemplateName"),
    ]:
        value = str(template.get(key_name, "")).strip()
        if value:
            optional_fields.append(f"            <{tag_name}>{escape(value)}</{tag_name}>")

    for required_field, tag_name in [
        ("securityProfileName", "securityProfileName"),
        ("phoneTemplateName", "phoneTemplateName"),
    ]:
        required_value = str(template.get(required_field, "")).strip()
        if not required_value:
            raise RuntimeError(f"Template field '{required_field}' is required")
        optional_fields.append(f"            <{tag_name}>{escape(required_value)}</{tag_name}>")

    display_name = " ".join(
        p for p in [user_details.get("firstName", ""), user_details.get("lastName", "")] if p
    ).strip() or user_details.get("displayName", "") or user_details["userid"]

    description = f"{description_prefix} {display_name}".strip()

    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:addPhone>
         <phone>
            <name>{escape(new_phone_name)}</name>
            <description>{escape(description)}</description>
            <product>{escape(str(template['product']))}</product>
            <class>{escape(str(template['class']))}</class>
            <protocol>{escape(str(template['protocol']))}</protocol>
            <protocolSide>{escape(str(template['protocolSide']))}</protocolSide>
            {chr(10).join(optional_fields)}
            <ownerUserName>{escape(user_details['userid'])}</ownerUserName>
            <lines>
               <line>
                  <index>1</index>
                  <dirn>
                     <pattern>{escape(dn_pattern)}</pattern>
                     <routePartitionName>{escape(dn_partition)}</routePartitionName>
                  </dirn>
                  <associatedEndusers>
                     <enduser>
                        <userId>{escape(user_details['userid'])}</userId>
                     </enduser>
                  </associatedEndusers>
                  <label>{escape(dn_pattern)}</label>
                  <display>{escape(display_name)}</display>
                  <displayAscii>{escape(display_name)}</displayAscii>
                  <e164Mask>{escape(dn_pattern)}</e164Mask>
                  <callInfoDisplay>
                     <callerName>true</callerName>
                     <callerNumber>true</callerNumber>
                     <redirectedNumber>true</redirectedNumber>
                     <dialedNumber>true</dialedNumber>
                  </callInfoDisplay>
                  <maxNumCalls>{escape(str(template['lineMaxNumCalls']))}</maxNumCalls>
                  <busyTrigger>{escape(str(template['lineBusyTrigger']))}</busyTrigger>
               </line>
            </lines>
         </phone>
      </axl:addPhone>
   </soapenv:Body>
</soapenv:Envelope>"""


def _build_update_user_devices_soap(userid, associated_devices):
    device_xml = "\n".join(
        f"            <device>{escape(device)}</device>" for device in associated_devices
    )

    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
   <soapenv:Body>
      <axl:updateUser>
         <userid>{escape(userid)}</userid>
         <associatedDevices>
{device_xml}
         </associatedDevices>
      </axl:updateUser>
   </soapenv:Body>
</soapenv:Envelope>"""


def _run_secondary_add(cucm_host, cucm_user, cucm_pass, target_user, options, output_prefix):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_user = (target_user or "").strip()
    filename = f"{output_prefix}_{clean_user or 'unknown'}_{ts}.csv"

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])

    if not clean_user:
        writer.writerow(["Validation", "Failed", "target_user is required"])
        return out.getvalue().encode("utf-8"), filename

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    try:
        user_details = _get_user_details(session, cucm_host, clean_user)
        writer.writerow(["Lookup User", "Success", f"Found {user_details['userid']}"])

        dn_pattern = (user_details.get("primaryExtension", {}).get("pattern") or "").strip()
        dn_partition = (user_details.get("primaryExtension", {}).get("routePartitionName") or "").strip() or DEFAULT_ROUTE_PARTITION

        if not dn_pattern:
            raise RuntimeError("End User does not have a primary extension. Set primary extension first, then rerun.")

        writer.writerow(["Resolve DN", "Success", f"Using End User primary extension {dn_pattern}/{dn_partition}"])

        templates = {}
        for option in options:
            template_file = option["template_file"]
            if template_file not in templates:
                templates[template_file] = _load_template(template_file)

        current_devices = list(user_details.get("associatedDevices", []))
        created_any = False

        for option in options:
            prefix = option["prefix"]
            label = option["label"]
            template = templates[option["template_file"]]
            new_device = f"{prefix}{dn_pattern}"

            writer.writerow([f"Resolve {label} Device Name", "Success", f"Target device name {new_device}"])

            if new_device in current_devices:
                writer.writerow([f"Check {label} Device", "Skipped", f"{new_device} already associated to user"])
                continue

            if _phone_exists(session, cucm_host, new_device):
                raise RuntimeError(f"Target device {new_device} already exists in CUCM. Choose a different approach.")

            writer.writerow([
                f"{label} Template",
                "Success",
                (
                    f"product={template['product']}; class={template['class']}; protocol={template['protocol']}; "
                    f"securityProfile={template['securityProfileName']}; phoneTemplate={template['phoneTemplateName']}"
                ),
            ])

            add_phone_soap = _build_add_phone_soap(
                user_details,
                new_device,
                dn_pattern,
                dn_partition,
                template,
                label,
            )
            add_phone_resp = _axl_post(session, cucm_host, add_phone_soap)
            if add_phone_resp.status_code != 200:
                raise RuntimeError(
                    f"Add {label} phone failed HTTP {add_phone_resp.status_code}: {add_phone_resp.text[:1200]}"
                )

            writer.writerow([f"Add {label} Device", "Success", f"Created {new_device} with shared DN {dn_pattern}"])
            current_devices.append(new_device)
            created_any = True

        if created_any:
            update_user_soap = _build_update_user_devices_soap(user_details["userid"], current_devices)
            update_user_resp = _axl_post(session, cucm_host, update_user_soap)
            if update_user_resp.status_code != 200:
                raise RuntimeError(
                    f"Update user association failed HTTP {update_user_resp.status_code}: {update_user_resp.text[:1200]}"
                )
            writer.writerow(["Update End User", "Success", f"Associated new device(s) to user {user_details['userid']}"])
        else:
            writer.writerow(["Update End User", "Skipped", "No new secondary device needed"])

    except Exception as exc:
        writer.writerow(["Script", "Error", str(exc)])

    return out.getvalue().encode("utf-8"), filename


def add_secondary_tct_device(cucm_host, cucm_user, cucm_pass, target_user):
    return _run_secondary_add(
        cucm_host,
        cucm_user,
        cucm_pass,
        target_user,
        options=[
            {
                "prefix": "TCT",
                "label": "TCT",
                "template_file": TCT_TEMPLATE_FILE,
            }
        ],
        output_prefix="add_secondary_tct",
    )


def add_secondary_bot_device(cucm_host, cucm_user, cucm_pass, target_user):
    return _run_secondary_add(
        cucm_host,
        cucm_user,
        cucm_pass,
        target_user,
        options=[
            {
                "prefix": "BOT",
                "label": "BOT",
                "template_file": BOT_TEMPLATE_FILE,
            }
        ],
        output_prefix="add_secondary_bot",
    )


def add_secondary_strike_devices(cucm_host, cucm_user, cucm_pass, target_user):
    return _run_secondary_add(
        cucm_host,
        cucm_user,
        cucm_pass,
        target_user,
        options=[
            {
                "prefix": "TCT",
                "label": "TCT",
                "template_file": TCT_TEMPLATE_FILE,
            },
            {
                "prefix": "BOT",
                "label": "BOT",
                "template_file": BOT_TEMPLATE_FILE,
            },
        ],
        output_prefix="add_secondary_strike",
    )

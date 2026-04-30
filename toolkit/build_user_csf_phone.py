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

LAB_CUCM_IP = "lascucmpl01.ahs.int"
PROD_CUCM_IP = "lascucmpp01.ahs.int"
TEMPLATE_FILE = "phone_device_template_lab_csf.json"
ROUTE_PARTITION = "ENT_DEVICE_PT"
UNITY_LAB_SERVER = "LASCUTYPL01.ahs.int"
UNITY_PROD_SERVER = "SANCUTYP01.ahs.int"
DEFAULT_VM_PIN = "56219"
LDAP_INTEGRATION_ENABLED = True
UNITY_ENV_SETTINGS = {
    "LAB": {
        "server": UNITY_LAB_SERVER,
        "template_alias": "T3-CST",
        "default_pin": DEFAULT_VM_PIN,
        "ldap_import_enabled": True,
    },
    "PRODUCTION": {
        "server": UNITY_PROD_SERVER,
        "template_alias": "T3-CST",
        "default_pin": DEFAULT_VM_PIN,
        "ldap_import_enabled": True,
    },
}


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


def _extract_object_id_from_location(response):
    location = response.headers.get("Location", "").strip()
    if not location:
        return None
    clean = location.rstrip("/")
    if "/vmrest/users/" not in clean:
        return None
    return clean.split("/")[-1] or None


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


def _get_unity_user_by_object_id(session, unity_server, object_id):
    url = _make_unity_url(unity_server, f"/vmrest/users/{object_id}")
    response = session.get(url, headers=_unity_headers(), timeout=120)
    if response.status_code != 200:
        raise RuntimeError(f"Unity user detail lookup failed: {_parse_unity_error_text(response)}")

    try:
        data = response.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _user_is_ldap_integrated(user, expected_ldap_user_id=None):
    if not isinstance(user, dict):
        return False

    integrated_flag = user.get("IsLdapIntegrated")
    if isinstance(integrated_flag, bool) and integrated_flag:
        return True
    if isinstance(integrated_flag, str) and integrated_flag.strip().lower() in {"true", "1", "yes"}:
        return True

    ldap_type = str(user.get("LdapType") or "").strip()
    ldap_pkid = str(user.get("LdapCcmPkid") or "").strip()
    ldap_user_id = str(user.get("LdapCcmUserId") or "").strip()
    if ldap_type == "3" and ldap_pkid:
        if not expected_ldap_user_id:
            return True
        return ldap_user_id.lower() == str(expected_ldap_user_id).strip().lower()

    return False


def _get_import_user_by_alias(session, unity_server, alias):
    endpoint = _make_unity_url(unity_server, "/vmrest/import/users/ldap")
    queries = [
        f"(alias is {alias})",
        f"(alias is {alias.lower()})",
        f"(alias startswith {alias.split('.')[0]})",
    ]

    for query in queries:
        response = session.get(endpoint, headers=_unity_headers(), params={"query": query}, timeout=120)
        if response.status_code == 404:
            raise RuntimeError("Unity import endpoint /vmrest/import/users/ldap is not available.")
        if response.status_code in {401, 403}:
            raise RuntimeError("Access denied for Unity import endpoint with current credentials.")
        if response.status_code != 200 or not response.text:
            continue

        try:
            data = response.json()
        except ValueError:
            continue

        import_users = data.get("ImportUser")
        if isinstance(import_users, dict):
            import_users = [import_users]
        if not isinstance(import_users, list) or not import_users:
            continue

        for import_user in import_users:
            if str(import_user.get("alias", "")).strip().lower() == alias.lower():
                return import_user

        if len(import_users) == 1:
            return import_users[0]

    return None


def _import_ldap_user_with_new_vm(session, unity_server, import_pkid, extension, template_alias):
    endpoint = _make_unity_url(unity_server, "/vmrest/import/users/ldap")
    payload = {
        "dtmfAccessId": extension,
        "pkid": import_pkid,
    }
    response = session.post(
        endpoint,
        headers=_unity_headers(),
        params={"templateAlias": template_alias},
        json=payload,
        timeout=120,
    )
    if response.status_code not in {200, 201, 204}:
        raise RuntimeError(f"Unity LDAP import failed: {_parse_unity_error_text(response)}")

    object_id = _extract_object_id_from_location(response)
    if object_id:
        return object_id

    body_text = (response.text or "").strip()
    if "/vmrest/users/" in body_text:
        return body_text.rstrip("/").split("/")[-1]

    return None


def _create_local_unity_user_with_mailbox(
    session, unity_server, alias, first_name, last_name, display_name, extension, email_address, template_alias
):
    url = _make_unity_url(unity_server, "/vmrest/users")
    payload = {
        "Alias": alias,
        "FirstName": first_name,
        "LastName": last_name,
        "DisplayName": display_name,
        "DtmfAccessId": extension,
        "EmailAddress": email_address,
        "IsLdapIntegrated": LDAP_INTEGRATION_ENABLED,
        "TemplateAlias": template_alias,
    }

    response = session.post(url, headers=_unity_headers(), json=payload, timeout=120)
    if response.status_code not in {200, 201}:
        retry = session.post(
            url,
            headers=_unity_headers(),
            params={"templateAlias": template_alias},
            json={
                "Alias": alias,
                "FirstName": first_name,
                "LastName": last_name,
                "DisplayName": display_name,
                "DtmfAccessId": extension,
                "EmailAddress": email_address,
                "IsLdapIntegrated": LDAP_INTEGRATION_ENABLED,
            },
            timeout=120,
        )
        if retry.status_code not in {200, 201}:
            raise RuntimeError(f"Unity local user create failed: {_parse_unity_error_text(retry)}")
        response = retry

    if response.text:
        try:
            data = response.json()
            return data.get("ObjectId") or _extract_object_id_from_location(response)
        except ValueError:
            return _extract_object_id_from_location(response)

    return _extract_object_id_from_location(response)


def _update_existing_unity_user_mailbox(session, unity_server, object_id, extension, email_address):
    url = _make_unity_url(unity_server, f"/vmrest/users/{object_id}")
    payload = {
        "DtmfAccessId": extension,
        "EmailAddress": email_address,
    }
    response = session.put(url, headers=_unity_headers(), json=payload, timeout=120)
    if response.status_code not in {200, 204}:
        raise RuntimeError(f"Unity mailbox update failed: {_parse_unity_error_text(response)}")


def _set_unity_pin(session, unity_server, object_id, pin):
    url = _make_unity_url(unity_server, f"/vmrest/users/{object_id}/credential/pin")
    payload = {
        "Credentials": pin,
        "CredMustChange": "true",
    }
    response = session.put(url, headers=_unity_headers(), json=payload, timeout=120)
    if response.status_code not in {200, 201, 204}:
        raise RuntimeError(f"Unity PIN update failed: {_parse_unity_error_text(response)}")


def _create_or_update_unity_voicemail(
    session,
    unity_server,
    alias,
    first_name,
    last_name,
    display_name,
    extension,
    email_address,
    template_alias,
    ldap_import_enabled,
):
    existing_user = _get_unity_user_by_alias(session, unity_server, alias)
    if existing_user:
        object_id = existing_user.get("ObjectId")
        if not object_id:
            raise RuntimeError("Unity user exists but ObjectId is missing.")
        _update_existing_unity_user_mailbox(session, unity_server, object_id, extension, email_address)
        return object_id, "updated"

    if ldap_import_enabled:
        import_user = _get_import_user_by_alias(session, unity_server, alias)
        if import_user and import_user.get("pkid"):
            object_id = _import_ldap_user_with_new_vm(
                session,
                unity_server,
                import_user.get("pkid"),
                extension,
                template_alias,
            )
            if object_id:
                return object_id, "imported"

    object_id = _create_local_unity_user_with_mailbox(
        session,
        unity_server,
        alias,
        first_name,
        last_name,
        display_name,
        extension,
        email_address,
        template_alias,
    )
    return object_id, "created_local"


def _get_user_details(session, cucm_ip, username):
    soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
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

    return {
        "userid": _find_first_text(user_node, [["userid"]]),
        "firstName": _find_first_text(user_node, [["firstName"]]),
        "lastName": _find_first_text(user_node, [["lastName"]]),
        "displayName": _find_first_text(user_node, [["displayName"]]),
        "mailid": _find_first_text(user_node, [["mailid"]]),
        "associatedDevices": associated_devices,
    }


def _list_available_dns(session, cucm_ip, prefix):
    soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
   <soapenv:Body>
      <axl:listLine>
         <searchCriteria>
            <pattern>{escape(prefix)}%</pattern>
         </searchCriteria>
         <returnedTags>
            <pattern/>
            <routePartitionName/>
            <active/>
         </returnedTags>
      </axl:listLine>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_ip, soap)
    if response.status_code != 200:
        raise RuntimeError(f"listLine for prefix {prefix} failed with HTTP {response.status_code}: {response.text[:1000]}")

    root = ET.fromstring(response.text)
    candidates = []
    for elem in root.iter():
        if _strip_ns(elem.tag) != "line":
            continue

        pattern = _find_first_text(elem, [["pattern"]])
        partition = _find_first_text(elem, [["routePartitionName"]])
        active = _find_first_text(elem, [["active"]]).strip().lower()

        is_inactive = active not in {"true", "t", "1", "yes"}
        if pattern and partition == ROUTE_PARTITION and is_inactive:
            candidates.append(pattern)

    return sorted(set(candidates))


def _is_dn_unassigned(session, cucm_ip, pattern, route_partition):
    soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
   <soapenv:Body>
      <axl:getLine>
         <pattern>{escape(pattern)}</pattern>
         <routePartitionName>{escape(route_partition)}</routePartitionName>
         <returnedTags>
            <pattern/>
            <routePartitionName/>
            <associatedDevices>
               <device/>
            </associatedDevices>
         </returnedTags>
      </axl:getLine>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_ip, soap)
    if response.status_code != 200:
        return False

    try:
        root = ET.fromstring(response.text)
    except Exception:
        return False

    for elem in root.iter():
        if _strip_ns(elem.tag) == "device" and elem.text and elem.text.strip():
            return False

    return True


def _choose_available_dn(session, cucm_ip, prefix):
    candidates = _list_available_dns(session, cucm_ip, prefix)
    for candidate in candidates:
        if _is_dn_unassigned(session, cucm_ip, candidate, ROUTE_PARTITION):
            return candidate
    raise RuntimeError(f"No available inactive DN found in {ROUTE_PARTITION} starting with {prefix}.")


def _build_add_phone_soap(template, user_details, phone_name, description, new_dn, display_name):
    optional_fields = []
    for tag_name, key_name in [
        ("callingSearchSpaceName", "callingSearchSpaceName"),
        ("devicePoolName", "devicePoolName"),
        ("commonPhoneConfigName", "commonPhoneConfigName"),
        ("locationName", "locationName"),
        ("mediaResourceListName", "mediaResourceListName"),
        ("securityProfileName", "securityProfileName"),
        ("sipProfileName", "sipProfileName"),
        ("phoneTemplateName", "phoneTemplateName"),
        ("presenceGroupName", "presenceGroupName"),
        ("subscribeCallingSearchSpaceName", "subscribeCallingSearchSpaceName"),
        ("rerouteCallingSearchSpaceName", "rerouteCallingSearchSpaceName"),
        ("userLocale", "userLocale"),
        ("networkLocale", "networkLocale"),
    ]:
        value = template.get(key_name, "").strip()
        if value:
            optional_fields.append(f"            <{tag_name}>{escape(value)}</{tag_name}>")

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
   <soapenv:Body>
      <axl:addPhone>
         <phone>
            <name>{escape(phone_name)}</name>
            <description>{escape(description)}</description>
            <product>{escape(template['product'])}</product>
            <class>{escape(template['class'])}</class>
            <protocol>{escape(template['protocol'])}</protocol>
            <protocolSide>{escape(template['protocolSide'])}</protocolSide>
            {chr(10).join(optional_fields)}
            <ownerUserName>{escape(user_details['userid'])}</ownerUserName>
            <lines>
               <line>
                  <index>1</index>
                  <dirn>
                     <pattern>{escape(new_dn)}</pattern>
                     <routePartitionName>{escape(template['routePartitionName'])}</routePartitionName>
                  </dirn>
                  <label>{escape(new_dn)}</label>
                  <display>{escape(display_name)}</display>
                  <displayAscii>{escape(display_name)}</displayAscii>
                  <alertingName>{escape(display_name)}</alertingName>
                  <asciiAlertingName>{escape(display_name)}</asciiAlertingName>
                  <e164Mask>{escape(new_dn)}</e164Mask>
                  <callInfoDisplay>
                     <callerName>true</callerName>
                     <callerNumber>true</callerNumber>
                     <redirectedNumber>true</redirectedNumber>
                     <dialedNumber>true</dialedNumber>
                  </callInfoDisplay>
                  <maxNumCalls>{escape(template['lineMaxNumCalls'])}</maxNumCalls>
                  <busyTrigger>{escape(template['lineBusyTrigger'])}</busyTrigger>
               </line>
            </lines>
         </phone>
      </axl:addPhone>
   </soapenv:Body>
</soapenv:Envelope>"""


def _build_update_line_soap(new_dn, route_partition, display_name):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
   <soapenv:Body>
      <axl:updateLine>
         <pattern>{escape(new_dn)}</pattern>
         <routePartitionName>{escape(route_partition)}</routePartitionName>
         <alertingName>{escape(display_name)}</alertingName>
         <asciiAlertingName>{escape(display_name)}</asciiAlertingName>
      </axl:updateLine>
   </soapenv:Body>
</soapenv:Envelope>"""


def _build_update_user_soap(user_details, phone_name, new_dn, route_partition, line_description):
    associated_devices = list(user_details["associatedDevices"])
    if phone_name not in associated_devices:
        associated_devices.append(phone_name)

    device_xml = "\n".join(
        f"            <device>{escape(device)}</device>" for device in associated_devices
    )

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
   <soapenv:Body>
      <axl:updateUser>
         <userid>{escape(user_details['userid'])}</userid>
         <associatedDevices>
{device_xml}
         </associatedDevices>
         <associatedGroups>
            <userGroup>
               <name>AMN User</name>
            </userGroup>
         </associatedGroups>
         <primaryExtension>
            <pattern>{escape(new_dn)}</pattern>
            <routePartitionName>{escape(route_partition)}</routePartitionName>
         </primaryExtension>
         <lineAppearanceAssociationForPresences>
            <lineAppearanceAssociationForPresence>
               <laapAssociate>t</laapAssociate>
               <laapProductType>Cisco Unified Client Services Framework</laapProductType>
               <laapDeviceName>{escape(phone_name)}</laapDeviceName>
               <laapDirectory>{escape(new_dn)}</laapDirectory>
               <laapPartition>{escape(route_partition)}</laapPartition>
               <laapDescription>{escape(line_description)}</laapDescription>
            </lineAppearanceAssociationForPresence>
         </lineAppearanceAssociationForPresences>
         <homeCluster>true</homeCluster>
         <serviceProfile>Service_Profile_IM</serviceProfile>
      </axl:updateUser>
   </soapenv:Body>
</soapenv:Envelope>"""


def _write_error_csv(message):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])
    writer.writerow(["Script", "Error", message])
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return out.getvalue().encode("utf-8"), f"build_user_csf_phone_error_{ts}.csv"


def build_user_csf_phone_from_template(
    cucm_host,
    cucm_user,
    cucm_pass,
    target_user,
    dn_type,
):
    dn_map = {
        "recruiter": ("469", "Recruiter"),
        "general": ("214", "General FTE"),
        "strike": ("945", "Strike"),
    }
    dn_prefix, dn_type_name = dn_map.get((dn_type or "").strip().lower(), ("214", "General FTE"))

    env_name = "PRODUCTION" if (cucm_host or "").strip().lower() == PROD_CUCM_IP else "LAB"
    unity_config = UNITY_ENV_SETTINGS[env_name]
    unity_server = unity_config["server"]
    unity_template_alias = unity_config["template_alias"]
    unity_default_pin = unity_config["default_pin"]
    unity_ldap_import_enabled = unity_config["ldap_import_enabled"]

    if not target_user or not target_user.strip():
        return _write_error_csv("target_user is required")

    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), TEMPLATE_FILE)
    if not os.path.exists(template_path):
        return _write_error_csv(f"Template file not found: {template_path}")

    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template = json.load(f)
    except Exception as e:
        return _write_error_csv(f"Invalid template JSON file {template_path}: {e}")

    required_template_keys = [
        "deviceNamePrefix",
        "product",
        "class",
        "protocol",
        "protocolSide",
        "routePartitionName",
        "lineMaxNumCalls",
        "lineBusyTrigger",
    ]
    missing = [k for k in required_template_keys if k not in template or str(template.get(k, "")).strip() == ""]
    if missing:
        return _write_error_csv(f"Template JSON missing required keys: {', '.join(missing)}")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"build_user_csf_phone_{target_user.strip()}_{ts}.csv"

    out = io.StringIO()
    log_writer = csv.writer(out)
    log_writer.writerow(["Step", "Status", "Details"])

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    unity_session = requests.Session()
    unity_session.verify = False
    unity_session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    try:
        user_details = _get_user_details(session, cucm_host, target_user.strip())
        full_name = " ".join(part for part in [user_details["firstName"], user_details["lastName"]] if part).strip()
        display_name = full_name or user_details["displayName"] or user_details["userid"]
        new_dn = _choose_available_dn(session, cucm_host, dn_prefix)
        phone_name = f"{template['deviceNamePrefix']}{new_dn}"
        description = f"CSF {display_name}".strip()

        log_writer.writerow(["Environment", "Success", f"{env_name} ({cucm_host})"])
        log_writer.writerow([
            "Unity Settings",
            "Info",
            (
                f"server={unity_server}; templateAlias={unity_template_alias}; "
                f"ldapImportEnabled={unity_ldap_import_enabled}; defaultPin={unity_default_pin}"
            ),
        ])
        log_writer.writerow(["DN Type", "Success", f"{dn_type_name} ({dn_prefix})"])
        log_writer.writerow(["Lookup User", "Success", f"Found user {user_details['userid']} ({display_name})"])
        log_writer.writerow(["Select DN", "Success", f"Using available DN {new_dn}"])

        add_phone_soap = _build_add_phone_soap(template, user_details, phone_name, description, new_dn, display_name)
        update_line_soap = _build_update_line_soap(new_dn, template["routePartitionName"], display_name)
        update_user_soap = _build_update_user_soap(user_details, phone_name, new_dn, template["routePartitionName"], description)

        add_response = _axl_post(session, cucm_host, add_phone_soap)
        if add_response.status_code != 200:
            log_writer.writerow(["Add Phone", "Failed", f"HTTP {add_response.status_code}: {add_response.text[:1000]}"])
            return out.getvalue().encode("utf-8"), filename

        log_writer.writerow(["Add Phone", "Success", f"Created {phone_name} with DN {new_dn}"])

        line_response = _axl_post(session, cucm_host, update_line_soap)
        if line_response.status_code != 200:
            log_writer.writerow(["Update Line", "Failed", f"HTTP {line_response.status_code}: {line_response.text[:1000]}"])
            return out.getvalue().encode("utf-8"), filename

        log_writer.writerow(["Update Line", "Success", f"Updated alerting names on DN {new_dn}"])

        update_response = _axl_post(session, cucm_host, update_user_soap)
        if update_response.status_code != 200:
            log_writer.writerow(["Update User", "Failed", f"HTTP {update_response.status_code}: {update_response.text[:1000]}"])
            return out.getvalue().encode("utf-8"), filename

        log_writer.writerow(["Update User", "Success", f"Updated {user_details['userid']} with phone {phone_name} and DN {new_dn}"])

        unity_email = user_details.get("mailid", "").strip() or f"{user_details['userid'].lower()}@amnhealthcare.com"
        unity_first = user_details.get("firstName", "").strip() or user_details["userid"]
        unity_last = user_details.get("lastName", "").strip() or user_details["userid"]

        unity_object_id, unity_action = _create_or_update_unity_voicemail(
            unity_session,
            unity_server,
            user_details["userid"],
            unity_first,
            unity_last,
            display_name,
            new_dn,
            unity_email,
            unity_template_alias,
            unity_ldap_import_enabled,
        )
        log_writer.writerow([
            "Unity Voicemail",
            "Success",
            f"{unity_action} Unity mailbox for {user_details['userid']} on {unity_server} using extension {new_dn}",
        ])

        latest_unity_user = _get_unity_user_by_object_id(unity_session, unity_server, unity_object_id)
        if latest_unity_user and not _user_is_ldap_integrated(latest_unity_user, user_details["userid"]):
            log_writer.writerow([
                "Unity LDAP Integration",
                "Manual",
                "User is not LDAP integrated in Unity; verify Integrate with LDAP Directory checkbox manually.",
            ])
        else:
            _set_unity_pin(unity_session, unity_server, unity_object_id, unity_default_pin)
            log_writer.writerow([
                "Unity PIN",
                "Success",
                f"Set default PIN ({unity_default_pin}) and forced change for {user_details['userid']}",
            ])

    except Exception as e:
        err_msg = str(e)
        if "The specified User was not found" in err_msg or "5007" in err_msg:
            log_writer.writerow(["Lookup User", "Failed", f"Invalid user: {target_user.strip()} was not found in CUCM"])
        else:
            log_writer.writerow(["Script", "Error", err_msg])

    return out.getvalue().encode("utf-8"), filename
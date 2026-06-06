import csv
import datetime
import io
import os
import smtplib
import xml.etree.ElementTree as ET
from email.message import EmailMessage

import requests
import urllib3
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape

try:
    from .ad_phone_fields import update_ad_phone_fields
except ImportError:
    from ad_phone_fields import update_ad_phone_fields

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AXL_NS = "http://www.cisco.com/AXL/API/15.0"
DN_ROUTE_PARTITION = "ENT_DEVICE_PT"
AUTO_DN_PREFIXES = ("214", "469", "945")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp1.ahs.int").strip() or "smtp1.ahs.int"
SMTP_PORT = int(os.getenv("SMTP_PORT", "25") or "25")
SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS", "12") or "12")
TEAMS_HANDOFF_EMAIL_FROM = os.getenv("TEAMS_HANDOFF_EMAIL_FROM", "noreply@amnhealthcare.com").strip() or "noreply@amnhealthcare.com"
ADMIN_EMAIL_DOMAIN = os.getenv("ADMIN_EMAIL_DOMAIN", "amnhealthcare.com").strip() or "amnhealthcare.com"
# Permanent Teams translation pattern template.
PERMANENT_TEMPLATE_FIELDS = {
    "transPattern.blockEnable": "false",
    "transPattern.calledPartyNumberType": "Cisco CallManager",
    "transPattern.calledPartyNumberingPlan": "Cisco CallManager",
    "transPattern.callingLinePresentationBit": "Default",
    "transPattern.callingNamePresentationBit": "Default",
    "transPattern.callingPartyNumberType": "Cisco CallManager",
    "transPattern.callingPartyNumberingPlan": "Cisco CallManager",
    "transPattern.callingSearchSpaceName": "Route_MS_TEAMS_CSS",
    "transPattern.callingSearchSpaceName.@uuid": "{1259CD4F-1527-419E-76FB-53C85F06E937}",
    "transPattern.connectedLinePresentationBit": "Default",
    "transPattern.connectedNamePresentationBit": "Default",
    "transPattern.dontWaitForIDTOnSubsequentHops": "false",
    "transPattern.isEmergencyServiceNumber": "false",
    "transPattern.patternPrecedence": "Default",
    "transPattern.patternUrgency": "false",
    "transPattern.provideOutsideDialtone": "false",
    "transPattern.releaseClause": "No Error",
    "transPattern.routeClass": "Default",
    "transPattern.routeNextHopByCgpn": "false",
    "transPattern.routePartitionName": "ENT_TEAMS_DEVICE_PT",
    "transPattern.routePartitionName.@uuid": "{14477090-D60E-4BDC-CA46-BFCFD33AA983}",
    "transPattern.usage": "Translation",
    "transPattern.useCallingPartyPhoneMask": "Off",
    "transPattern.useOriginatorCss": "false",
}


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


def _axl_post(session, cucm_host, soap_xml):
    response = session.post(
        f"https://{cucm_host}:8443/axl/",
        data=soap_xml.encode("utf-8"),
        headers={"Content-Type": "text/xml"},
        timeout=120,
    )
    return response


def _get_user_details(session, cucm_host, username):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
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

    return {
        "userid": _find_first_text(user_node, [["userid"]]),
        "firstName": _find_first_text(user_node, [["firstName"]]),
        "lastName": _find_first_text(user_node, [["lastName"]]),
        "displayName": _find_first_text(user_node, [["displayName"]]),
        "mailid": _find_first_text(user_node, [["mailid"]]),
    }


def _list_available_dns(session, cucm_host, prefix):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
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

    response = _axl_post(session, cucm_host, soap)
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
        if pattern and partition == DN_ROUTE_PARTITION and is_inactive:
            candidates.append(pattern)

    return sorted(set(candidates))


def _is_dn_unassigned(session, cucm_host, pattern, route_partition):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
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

    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        return False

    root = ET.fromstring(response.text)
    for elem in root.iter():
        if _strip_ns(elem.tag) == "device" and elem.text and elem.text.strip():
            return False

    return True


def _choose_available_dn(session, cucm_host, prefix):
    candidates = _list_available_dns(session, cucm_host, prefix)
    for candidate in candidates:
        if _is_dn_unassigned(session, cucm_host, candidate, DN_ROUTE_PARTITION):
            return candidate
    raise RuntimeError(f"No available inactive DN found in {DN_ROUTE_PARTITION} starting with {prefix}.")


def _choose_available_dn_auto(session, cucm_host):
    for prefix in AUTO_DN_PREFIXES:
        try:
            chosen = _choose_available_dn(session, cucm_host, prefix)
            return chosen, prefix
        except Exception:
            continue
    raise RuntimeError(
        "No available inactive DN found in ENT_DEVICE_PT for auto-selection prefixes: "
        + ", ".join(AUTO_DN_PREFIXES)
    )


def _remove_line(session, cucm_host, pattern, route_partition):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
   <soapenv:Body>
      <axl:removeLine>
         <pattern>{escape(pattern)}</pattern>
         <routePartitionName>{escape(route_partition)}</routePartitionName>
      </axl:removeLine>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        raise RuntimeError(f"removeLine failed HTTP {response.status_code}: {response.text[:1200]}")


def _build_add_trans_pattern_soap(pattern, description, full_fields):
    ordered_fields = [
        "usage",
        "routePartitionName",
        "blockEnable",
        "useCallingPartyPhoneMask",
        "patternUrgency",
        "callingLinePresentationBit",
        "callingNamePresentationBit",
        "connectedLinePresentationBit",
        "connectedNamePresentationBit",
        "patternPrecedence",
        "provideOutsideDialtone",
        "callingPartyNumberingPlan",
        "callingPartyNumberType",
        "calledPartyNumberingPlan",
        "calledPartyNumberType",
        "callingSearchSpaceName",
        "routeNextHopByCgpn",
        "routeClass",
        "releaseClause",
        "useOriginatorCss",
        "dontWaitForIDTOnSubsequentHops",
        "isEmergencyServiceNumber",
        "calledPartyTransformationMask",
        "callingPartyTransformationMask",
    ]

    values = {}
    for key, value in (full_fields or {}).items():
        if not key.startswith("transPattern."):
            continue
        suffix = key[len("transPattern."):]
        if ".@" in suffix or "[" in suffix:
            continue
        if suffix in {"pattern", "description"}:
            continue
        clean_val = str(value or "").strip()
        if clean_val:
            values[suffix] = clean_val

    extra_xml = []
    for field in ordered_fields:
        if field in values:
            extra_xml.append(f"            <{field}>{escape(values[field])}</{field}>")

    # Add any additional fields from the template that are not in ordered list.
    for field in sorted(values.keys()):
        if field in ordered_fields:
            continue
        extra_xml.append(f"            <{field}>{escape(values[field])}</{field}>")

    return f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
   <soapenv:Body>
      <axl:addTransPattern>
         <transPattern>
            <pattern>{escape(pattern)}</pattern>
            <description>{escape(description)}</description>
{chr(10).join(extra_xml)}
         </transPattern>
      </axl:addTransPattern>
   </soapenv:Body>
</soapenv:Envelope>"""


def _add_translation_pattern(session, cucm_host, pattern, description, full_fields):
    soap = _build_add_trans_pattern_soap(pattern, description, full_fields)
    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        raise RuntimeError(f"addTransPattern failed HTTP {response.status_code}: {response.text[:1200]}")


def _powershell_handoff_template(email, dn):
    plus_one_dn = f"+1{dn}"
    return "\n".join([
        f"Set-CsPhoneNumberAssignment -Identity \"{email}\" -EnterpriseVoiceEnabled $true",
        f"Set-CsPhoneNumberAssignment -Identity \"{email}\" -PhoneNumber {plus_one_dn} -PhoneNumberType DirectRouting",
        f"Grant-CsOnlineVoiceRoutingPolicy -Identity \"{email}\" -PolicyName \"Unrestricted\"",
        f"Grant-CsDialoutPolicy -Identity \"{email}\" -PolicyName \"DialoutCPCDomesticPSTNInternational\"",
    ])


def _resolve_admin_email(operator_username):
    user = (operator_username or "").strip()
    if not user:
        return ""

    # If username is email-like, use local part only and enforce AMN domain.
    alias = user.split("@", 1)[0].strip()
    lower_alias = alias.lower()
    if lower_alias.endswith(".adm"):
        alias = alias[:-4]
    elif lower_alias.endswith(".ad"):
        alias = alias[:-3]

    alias = alias.strip(".")
    if not alias or "." not in alias:
        return ""

    return f"{alias}@{ADMIN_EMAIL_DOMAIN}"


def _send_handoff_email_to_admin(operator_username, target_userid, target_email, dn, ps_commands):
    admin_email = _resolve_admin_email(operator_username)
    if not admin_email:
        return False, "Could not derive admin email from operator username. Use firstname.lastname format."

    subject = f"Teams Telephony Handoff Commands - {target_userid}"
    body = "\n".join([
        "1. Go to MS User - assign license manually - Microsoft Teams Phone Standard",
        "",
        "2. User Power shell - Only Greg and Chris access or office 365 admin besides Roger;s automation - make sure they have most recent Microsoft Teams module - use latest version",
        "",
        "5 commands to run:",
        "Connect-MicrosoftTeams",
        "",
        ps_commands,
    ])

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = TEAMS_HANDOFF_EMAIL_FROM
    message["To"] = admin_email
    message.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.send_message(message)
    except Exception as exc:
        return False, f"Failed to send handoff email to {admin_email}: {exc}"

    return True, f"Sent handoff commands to {admin_email}"


def _load_saved_template_fields():
    return {
        "source_pattern": "",
        "source_route_partition": "ENT_TEAMS_DEVICE_PT",
        "full_fields": dict(PERMANENT_TEMPLATE_FIELDS),
        "template_origin": "permanent",
    }


def create_teams_telephony_user(
    cucm_host,
    cucm_user,
    cucm_pass,
    target_user,
    ad_username="",
    ad_password="",
):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = (target_user or "").strip()
    filename = f"create_teams_telephony_user_{clean_target or 'unknown'}_{ts}.csv"

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])

    if not clean_target:
        writer.writerow(["Validation", "Failed", "target_user is required"])
        return out.getvalue().encode("utf-8"), filename

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    try:
        user_details = _get_user_details(session, cucm_host, clean_target)
        email = (user_details.get("mailid") or "").strip()
        if not email:
            raise RuntimeError("Target user does not have mailid in CUCM.")

        display_name = " ".join(
            part for part in [user_details.get("firstName", ""), user_details.get("lastName", "")] if part
        ).strip() or user_details.get("displayName", "") or user_details.get("userid", clean_target)

        writer.writerow(["Lookup User", "Success", f"Found {user_details.get('userid', clean_target)}; email={email}"])

        detail = _load_saved_template_fields()
        writer.writerow([
            "Extract Template",
            "Success",
            "Using permanent built-in translation pattern template",
        ])

        new_dn, selected_prefix = _choose_available_dn_auto(session, cucm_host)
        writer.writerow([
            "Select Available DN",
            "Success",
            f"Selected {new_dn}/{DN_ROUTE_PARTITION} using auto-prefix {selected_prefix}",
        ])

        _remove_line(session, cucm_host, new_dn, DN_ROUTE_PARTITION)
        writer.writerow([
            "Delete Line",
            "Success",
            f"Deleted {new_dn}/{DN_ROUTE_PARTITION} before translation pattern rebuild",
        ])

        description = f"TEAMS DID {new_dn} {display_name}".strip()
        _add_translation_pattern(
            session,
            cucm_host,
            pattern=new_dn,
            description=description,
            full_fields=detail.get("full_fields", {}),
        )
        writer.writerow([
            "Add Translation Pattern",
            "Success",
            f"Created translation pattern {new_dn} with description '{description}'",
        ])

        ad_context = None
        if (ad_username or "").strip() and (ad_password or ""):
            ad_context = {
                "username": (ad_username or "").strip(),
                "password": ad_password,
            }
        ad_ok, ad_message = update_ad_phone_fields(user_details.get("userid", clean_target), new_dn, ad_context)
        writer.writerow([
            "Update AD Phone Fields",
            "Success" if ad_ok else "Failed",
            ad_message,
        ])

        ps_template = _powershell_handoff_template(email=email, dn=new_dn)
        writer.writerow([
            "PowerShell Handoff",
            "Success",
            ps_template,
        ])

        mail_ok, mail_msg = _send_handoff_email_to_admin(
            operator_username=cucm_user,
            target_userid=user_details.get("userid", clean_target),
            target_email=email,
            dn=new_dn,
            ps_commands=ps_template,
        )
        writer.writerow([
            "Email Admin Handoff",
            "Success" if mail_ok else "Failed",
            mail_msg,
        ])

    except Exception as exc:
        writer.writerow(["Script", "Error", str(exc)])

    return out.getvalue().encode("utf-8"), filename

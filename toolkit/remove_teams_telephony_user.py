import csv
import datetime
import io
import re
import xml.etree.ElementTree as ET

import requests
import urllib3
from requests.auth import HTTPBasicAuth
from xml.sax.saxutils import escape

from cucm_config import DEFAULT_ROUTE_PARTITION, TEAMS_ROUTE_PARTITION

try:
    from .ad_phone_fields import clear_ad_phone_fields
except ImportError:
    from ad_phone_fields import clear_ad_phone_fields

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AXL_NS = "http://www.cisco.com/AXL/API/15.0"
TEAMS_ROUTE_PARTITION = TEAMS_ROUTE_PARTITION
DEVICE_ROUTE_PARTITION = DEFAULT_ROUTE_PARTITION


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


def _normalize_did(value):
    digits = re.sub(r"\D", "", value or "")
    if len(digits) == 11 and digits.startswith("1"):
        return digits[1:]
    return digits


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
        "userid": _find_first_text(user_node, [["userid"]]) or username,
        "first_name": _find_first_text(user_node, [["firstName"]]),
        "last_name": _find_first_text(user_node, [["lastName"]]),
        "mailid": _find_first_text(user_node, [["mailid"]]),
        "extension": _find_first_text(user_node, [["primaryExtension", "pattern"]]),
        "telephone": _find_first_text(user_node, [["telephoneNumber"]]),
    }


def _list_translation_patterns(session, cucm_host, pattern_query):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
   <soapenv:Body>
      <axl:listTransPattern>
         <searchCriteria>
            <pattern>{escape(pattern_query)}</pattern>
         </searchCriteria>
         <returnedTags>
            <uuid/>
            <pattern/>
            <description/>
            <routePartitionName/>
         </returnedTags>
      </axl:listTransPattern>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        raise RuntimeError(f"listTransPattern failed with HTTP {response.status_code}: {response.text[:1200]}")

    root = ET.fromstring(response.text)
    results = []
    for elem in root.iter():
        if _strip_ns(elem.tag) != "transPattern":
            continue
        uuid_text = ""
        for key, value in elem.attrib.items():
            if key.lower().endswith("uuid") and (value or "").strip():
                uuid_text = value.strip()
                break
        if not uuid_text:
            uuid_text = _find_first_text(elem, [["uuid"]])

        results.append({
            "uuid": uuid_text,
            "pattern": _find_first_text(elem, [["pattern"]]),
            "description": _find_first_text(elem, [["description"]]),
            "route_partition": _find_first_text(elem, [["routePartitionName"]]),
        })

    return results


def _find_strict_teams_pattern_match(session, cucm_host, extension_or_telephone, first_name, last_name):
    ext_digits = _normalize_did(extension_or_telephone)
    if not ext_digits:
        raise RuntimeError("User has no primary extension or telephone number to match Teams translation pattern.")

    # Primary expectation: TEAMS DID <digits> <First Last>
    expected_description = f"TEAMS DID {ext_digits} {first_name} {last_name}".strip()
    expected_prefix = f"TEAMS DID {ext_digits}".strip().lower()
    expected_name = f"{first_name} {last_name}".strip().lower()
    candidates = _list_translation_patterns(session, cucm_host, ext_digits)

    best_prefix_only_match = None

    for item in candidates:
        pattern_digits = _normalize_did(item.get("pattern") or "")
        if pattern_digits != ext_digits:
            continue
        if (item.get("route_partition") or "").strip().lower() != TEAMS_ROUTE_PARTITION.lower():
            continue

        description = (item.get("description") or "").strip()
        desc_lc = description.lower()

        # Perfect match: prefix + full name present in description.
        if expected_prefix in desc_lc and (not expected_name or expected_name in desc_lc):
            return {
                "pattern": item.get("pattern") or ext_digits,
                "route_partition": item.get("route_partition") or TEAMS_ROUTE_PARTITION,
                "description": description,
                "expected_description": expected_description,
                "extension": ext_digits,
            }

        # Fallback candidate when name text differs slightly but DID marker matches.
        if expected_prefix in desc_lc and best_prefix_only_match is None:
            best_prefix_only_match = {
                "pattern": item.get("pattern") or ext_digits,
                "route_partition": item.get("route_partition") or TEAMS_ROUTE_PARTITION,
                "description": description,
                "expected_description": expected_description,
                "extension": ext_digits,
            }

    if best_prefix_only_match is not None:
        return best_prefix_only_match

    return {
        "pattern": "",
        "route_partition": "",
        "description": "",
        "expected_description": expected_description,
        "extension": ext_digits,
    }


def lookup_teams_telephony_removal_candidate(cucm_host, cucm_user, cucm_pass, target_user):
    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    clean_target = (target_user or "").strip()
    if not clean_target:
        raise RuntimeError("target_user is required")

    user = _get_user_details(session, cucm_host, clean_target)
    # For Teams DID mappings, telephone is the preferred match source.
    match_source = user.get("telephone", "") or user.get("extension", "")
    match = _find_strict_teams_pattern_match(
        session,
        cucm_host,
        match_source,
        user.get("first_name", ""),
        user.get("last_name", ""),
    )

    return {
        "target_user": user.get("userid", clean_target),
        "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""),
        "extension": match.get("extension", "") or _normalize_did(match_source),
        "expected_description": match.get("expected_description", ""),
        "match_found": bool(match.get("pattern")),
        "pattern": match.get("pattern", ""),
        "route_partition": match.get("route_partition", ""),
        "description": match.get("description", ""),
        "match_source": "telephoneNumber" if user.get("telephone", "") else "primaryExtension",
    }


def _remove_translation_pattern(session, cucm_host, pattern, route_partition):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
   <soapenv:Body>
      <axl:removeTransPattern>
         <pattern>{escape(pattern)}</pattern>
         <routePartitionName>{escape(route_partition)}</routePartitionName>
      </axl:removeTransPattern>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        raise RuntimeError(f"removeTransPattern failed HTTP {response.status_code}: {response.text[:1200]}")


def _add_inactive_directory_number(session, cucm_host, pattern):
    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"{AXL_NS}\">
   <soapenv:Body>
      <axl:addLine>
         <line>
            <pattern>{escape(pattern)}</pattern>
            <routePartitionName>{DEVICE_ROUTE_PARTITION}</routePartitionName>
            <description>CNAM:AMNHelathcare {escape(pattern)} Automation Use Only</description>
            <usage>Device</usage>
            <aarKeepCallHistory>true</aarKeepCallHistory>
            <aarVoiceMailEnabled>false</aarVoiceMailEnabled>
            <callForwardAll>
               <forwardToVoiceMail>false</forwardToVoiceMail>
               <callingSearchSpaceName>Cfwd_LD_CSS</callingSearchSpaceName>
            </callForwardAll>
            <callForwardBusy><forwardToVoiceMail>true</forwardToVoiceMail></callForwardBusy>
            <callForwardBusyInt><forwardToVoiceMail>true</forwardToVoiceMail></callForwardBusyInt>
            <callForwardNoAnswer><forwardToVoiceMail>true</forwardToVoiceMail></callForwardNoAnswer>
            <callForwardNoAnswerInt><forwardToVoiceMail>true</forwardToVoiceMail></callForwardNoAnswerInt>
            <callForwardNoCoverage><forwardToVoiceMail>true</forwardToVoiceMail></callForwardNoCoverage>
            <callForwardNoCoverageInt><forwardToVoiceMail>true</forwardToVoiceMail></callForwardNoCoverageInt>
            <callForwardOnFailure><forwardToVoiceMail>true</forwardToVoiceMail></callForwardOnFailure>
            <callForwardNotRegistered><forwardToVoiceMail>true</forwardToVoiceMail></callForwardNotRegistered>
            <callForwardNotRegisteredInt><forwardToVoiceMail>true</forwardToVoiceMail></callForwardNotRegisteredInt>
            <autoAnswer>Auto Answer Off</autoAnswer>
            <callingIdPresentationWhenDiverted>Default</callingIdPresentationWhenDiverted>
            <presenceGroupName>Standard Presence group</presenceGroupName>
            <shareLineAppearanceCssName>COR_Intl_CSS</shareLineAppearanceCssName>
            <voiceMailProfileName>VM_Profile_10Digits</voiceMailProfileName>
            <patternPrecedence>Default</patternPrecedence>
            <cfaCssPolicy>Use System Default</cfaCssPolicy>
            <partyEntranceTone>Default</partyEntranceTone>
            <allowCtiControlFlag>true</allowCtiControlFlag>
            <rejectAnonymousCall>false</rejectAnonymousCall>
            <patternUrgency>false</patternUrgency>
            <useEnterpriseAltNum>false</useEnterpriseAltNum>
            <useE164AltNum>false</useE164AltNum>
            <active>false</active>
         </line>
      </axl:addLine>
   </soapenv:Body>
</soapenv:Envelope>"""

    response = _axl_post(session, cucm_host, soap)
    if response.status_code != 200:
        raise RuntimeError(f"addLine failed HTTP {response.status_code}: {response.text[:1200]}")


def remove_teams_telephony_user(
    cucm_host,
    cucm_user,
    cucm_pass,
    target_user,
    ad_username="",
    ad_password="",
):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = (target_user or "").strip()
    filename = f"remove_teams_telephony_user_{clean_target or 'unknown'}_{ts}.csv"

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Step", "Status", "Details"])

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    try:
        lookup = lookup_teams_telephony_removal_candidate(
            cucm_host=cucm_host,
            cucm_user=cucm_user,
            cucm_pass=cucm_pass,
            target_user=clean_target,
        )

        writer.writerow([
            "Lookup User",
            "Success",
            f"{lookup.get('target_user', clean_target)} ({lookup.get('first_name', '')} {lookup.get('last_name', '')})",
        ])
        writer.writerow([
            "Get Extension",
            "Success" if lookup.get("extension") else "Failed",
            lookup.get("extension") or "No extension found on user",
        ])

        if not lookup.get("match_found"):
            writer.writerow([
                "Find Strict Teams Translation Pattern",
                "Failed",
                "No translation pattern matched strict description format: "
                + (lookup.get("expected_description") or "TEAMS DID <extension> <FirstName> <LastName>"),
            ])
            return out.getvalue().encode("utf-8"), filename

        writer.writerow([
            "Find Strict Teams Translation Pattern",
            "Success",
            f"{lookup.get('pattern')}/{lookup.get('route_partition')} | {lookup.get('description')}",
        ])

        _remove_translation_pattern(
            session,
            cucm_host,
            lookup.get("pattern", ""),
            lookup.get("route_partition", TEAMS_ROUTE_PARTITION),
        )
        writer.writerow([
            "Delete Translation Pattern",
            "Success",
            f"Deleted {lookup.get('pattern')}/{lookup.get('route_partition')}",
        ])

        _add_inactive_directory_number(session, cucm_host, lookup.get("extension", ""))
        writer.writerow([
            "Rebuild Inactive Directory Number",
            "Success",
            f"Rebuilt {lookup.get('extension')}/{DEVICE_ROUTE_PARTITION} as inactive DN",
        ])

        ad_context = None
        if (ad_username or "").strip() and (ad_password or ""):
            ad_context = {
                "username": (ad_username or "").strip(),
                "password": ad_password,
            }
        ad_ok, ad_message = clear_ad_phone_fields(lookup.get("target_user", clean_target), ad_context)
        writer.writerow([
            "Clear AD Phone Fields",
            "Success" if ad_ok else "Failed",
            ad_message,
        ])

    except Exception as exc:
        writer.writerow(["Script", "Error", str(exc)])

    return out.getvalue().encode("utf-8"), filename

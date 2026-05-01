import urllib3
import requests
from requests.auth import HTTPBasicAuth
import csv
import io
import datetime
import re
import xml.etree.ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
AXL_NS = "http://www.cisco.com/AXL/API/15.0"
NS = {"soapenv": SOAP_NS}

# v1 LOCKED BODY � DO NOT MODIFY
BODY_TEMPLATE = r"""<soapenv:Body>
 <axl:addLine>
 <line>
 <pattern>{pattern}</pattern>
 <routePartitionName>ENT_DEVICE_PT</routePartitionName>
 <description>CNAM:AMNHelathcare {pattern} Automation Use Only</description>
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
 </soapenv:Body>"""


def _soap_envelope(body_xml: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAP_NS}" xmlns:axl="{AXL_NS}">
  <soapenv:Header/>
{body_xml}
</soapenv:Envelope>"""


def _axl_post(session, cucm_host, soap_xml):
    url = f"https://{cucm_host}:8443/axl/"
    print(f"DEBUG AXL POST to {url}", flush=True)
    r = session.post(
        url,
        data=soap_xml.encode("utf-8"),
        headers={"Content-Type": "text/xml"},
        timeout=60,
        verify=False,
    )
    print(f"DEBUG AXL response status {r.status_code}", flush=True)
    r.raise_for_status()
    return r.text


def _parse_fault(xml):
    try:
        root = ET.fromstring(xml)
        body = root.find("soapenv:Body", NS)
        for child in body:
            if child.tag.endswith("Fault"):
                for el in child:
                    if el.tag.endswith("faultstring"):
                        return el.text or ""
        return ""
    except Exception:
        return ""


def _parse_manual_patterns(text: str):
    raw = re.split(r"[,\s]+", text.strip())
    return [x for x in raw if x.isdigit()]


def add_directory_numbers_from_csv(
    cucm_host, cucm_user, cucm_pass, csv_bytes, defaults
):
    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    patterns = []

    # ? PRIMARY PATH � MANUAL INPUT
    manual_text = defaults.get("manual_patterns", "").strip()
    if manual_text:
        patterns = _parse_manual_patterns(manual_text)

    # ? SECONDARY PATH � CSV (only if manual missing)
    if not patterns:
        if not csv_bytes:
            return _error_csv("NO_INPUT", "No manual numbers or CSV provided")

        text = csv_bytes.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(text))

        if not reader.fieldnames or "pattern" not in [
            h.strip().lower() for h in reader.fieldnames
        ]:
            return _error_csv("INVALID_CSV", "CSV must contain header 'pattern'")

        patterns = [
            row.get("pattern", "").strip()
            for row in reader
            if row.get("pattern")
        ]

    results = []

    for pattern in patterns:
        try:
            body = BODY_TEMPLATE.format(pattern=pattern)
            soap = _soap_envelope(body)
            _axl_post(session, cucm_host, soap)
            results.append([pattern, "OK", "Added"])
        except requests.exceptions.HTTPError as e:
            fault = _parse_fault(e.response.text) if e.response else str(e)
            results.append([pattern, "ERROR", fault])

    return _result_csv(results)


def _error_csv(code, detail):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["error", "detail"])
    w.writerow([code, detail])
    return out.getvalue().encode("utf-8"), "axl_error.csv"


def _result_csv(rows):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["pattern", "status", "detail"])
    w.writerows(rows)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return out.getvalue().encode("utf-8"), f"directory_add_log_{ts}.csv"

import csv
import datetime
import io
import re

import requests
from requests.auth import HTTPBasicAuth

try:
    from .ad_phone_fields import update_ad_phone_fields
    from .create_teams_telephony_user import (
        DN_ROUTE_PARTITION,
        _add_translation_pattern,
        _choose_available_dn_auto,
        _get_user_details,
        _remove_line,
    )
    from .remove_teams_telephony_user import (
        _add_inactive_directory_number,
        _get_user_details as _get_sms_lookup_user_details,
        _remove_translation_pattern,
    )
except ImportError:
    from ad_phone_fields import update_ad_phone_fields
    from create_teams_telephony_user import (
        DN_ROUTE_PARTITION,
        _add_translation_pattern,
        _choose_available_dn_auto,
        _get_user_details,
        _remove_line,
    )
    from remove_teams_telephony_user import (
        _add_inactive_directory_number,
        _get_user_details as _get_sms_lookup_user_details,
        _remove_translation_pattern,
    )

SMS_ROUTE_PARTITION = "ENT_DEVICE_PT"
SMS_CALLING_SEARCH_SPACE = "Route_Internal_CSS"
SMS_CALLED_PARTY_TRANSFORM_MASK = "2481009"
SMS_PATTERN_PAGE_SIZE = 1000
SMS_PATTERN_MAX_PAGES = 100

SMS_TEMPLATE_FIELDS = {
    "transPattern.blockEnable": "false",
    "transPattern.calledPartyNumberType": "Cisco CallManager",
    "transPattern.calledPartyNumberingPlan": "Cisco CallManager",
    "transPattern.callingLinePresentationBit": "Default",
    "transPattern.callingNamePresentationBit": "Default",
    "transPattern.callingPartyNumberType": "Cisco CallManager",
    "transPattern.callingPartyNumberingPlan": "Cisco CallManager",
    "transPattern.callingSearchSpaceName": SMS_CALLING_SEARCH_SPACE,
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
    "transPattern.routePartitionName": SMS_ROUTE_PARTITION,
    "transPattern.usage": "Translation",
    "transPattern.useCallingPartyPhoneMask": "Off",
    "transPattern.useOriginatorCss": "false",
    "transPattern.calledPartyTransformationMask": SMS_CALLED_PARTY_TRANSFORM_MASK,
}


def build_sms_description(first_name, last_name, extension):
    return f"SMS - {str(first_name or '').strip()} {str(last_name or '').strip()} {str(extension or '').strip()}".strip()


def _digits(value):
    return re.sub(r"\D", "", str(value or ""))


def find_sms_only_patterns_for_user(patterns, first_name, last_name, expected_number=""):
    clean_first = " ".join(str(first_name or "").split())
    clean_last = " ".join(str(last_name or "").split())
    if not clean_first or not clean_last:
        return []

    expected_prefix = f"SMS - {clean_first} {clean_last} "
    expected_digits = _digits(expected_number)
    if len(expected_digits) == 11 and expected_digits.startswith("1"):
        expected_digits = expected_digits[1:]
    matches = []
    for row in patterns or []:
        if not isinstance(row, dict):
            continue
        description = str(row.get("description", "") or "").strip()
        if not description.casefold().startswith("sms - "):
            continue
        if not description.casefold().startswith(expected_prefix.casefold()):
            continue
        described_extension = description[len(expected_prefix):].strip()
        if not re.fullmatch(r"\d{10}", described_extension):
            continue
        if expected_digits and described_extension != expected_digits:
            continue
        pattern = str(row.get("pattern", "") or "").strip()
        if _digits(pattern) != described_extension:
            continue
        if str(row.get("route_partition", "") or "").strip().casefold() != SMS_ROUTE_PARTITION.casefold():
            continue
        if str(row.get("called_party_transform_mask", "") or "").strip() != SMS_CALLED_PARTY_TRANSFORM_MASK:
            continue
        matches.append({**row, "pattern": pattern, "extension": described_extension})
    return sorted(matches, key=lambda row: (row["extension"], row["pattern"]))


def list_sms_only_patterns(cucm_host, cucm_user, cucm_pass, read_sql):
    rows_by_key = {}
    page_fingerprints = set()
    for page_number in range(SMS_PATTERN_MAX_PAGES):
        offset = page_number * SMS_PATTERN_PAGE_SIZE
        sql = (
            f"SELECT SKIP {offset} FIRST {SMS_PATTERN_PAGE_SIZE} "
            "n.dnorpattern AS pattern, n.description AS description, "
            "n.calledpartytransformationmask AS called_party_transform_mask, "
            "r.name AS route_partition "
            "FROM numplan n JOIN routepartition r ON r.pkid=n.fkroutepartition "
            "WHERE n.tkpatternusage IN (3,15) "
            f"AND r.name='{SMS_ROUTE_PARTITION}' "
            f"AND n.calledpartytransformationmask='{SMS_CALLED_PARTY_TRANSFORM_MASK}' "
            "AND n.description LIKE 'SMS - %' "
            "ORDER BY n.description, n.dnorpattern"
        )
        rows = read_sql(cucm_host, cucm_user, cucm_pass, sql)
        if not isinstance(rows, list) or len(rows) > SMS_PATTERN_PAGE_SIZE:
            raise RuntimeError("SMS translation-pattern inventory returned invalid data.")
        fingerprint = tuple(
            (
                str(row.get("pattern", "") or "").strip(),
                str(row.get("route_partition", "") or "").strip(),
                str(row.get("description", "") or "").strip(),
            )
            for row in rows if isinstance(row, dict)
        )
        if rows and (len(fingerprint) != len(rows) or fingerprint in page_fingerprints):
            raise RuntimeError("SMS translation-pattern inventory returned a repeated or invalid page.")
        page_fingerprints.add(fingerprint)
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("SMS translation-pattern inventory returned an invalid record.")
            pattern = str(row.get("pattern", "") or "").strip()
            description = str(row.get("description", "") or "").strip()
            partition = str(row.get("route_partition", "") or "").strip()
            mask = str(row.get("called_party_transform_mask", "") or "").strip()
            if not pattern or not description or not partition or not mask:
                raise RuntimeError("SMS translation-pattern inventory omitted required fields.")
            key = (pattern, partition.casefold())
            if key in rows_by_key:
                raise RuntimeError("SMS translation-pattern inventory returned a duplicate pattern.")
            rows_by_key[key] = {
                "pattern": pattern,
                "description": description,
                "route_partition": partition,
                "called_party_transform_mask": mask,
            }
        if len(rows) < SMS_PATTERN_PAGE_SIZE:
            return list(rows_by_key.values())
    raise RuntimeError(f"SMS translation-pattern inventory exceeded {SMS_PATTERN_MAX_PAGES} pages.")


def lookup_sms_only_user(cucm_host, cucm_user, cucm_pass, target_user, read_sql):
    clean_target = str(target_user or "").strip()
    if not clean_target:
        raise RuntimeError("target_user is required")
    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)
    user = _get_sms_lookup_user_details(session, cucm_host, clean_target)
    patterns = list_sms_only_patterns(cucm_host, cucm_user, cucm_pass, read_sql)
    expected_number = str(user.get("telephone", "") or user.get("extension", "") or "").strip()
    name_matches = find_sms_only_patterns_for_user(patterns, user.get("first_name", ""), user.get("last_name", ""))
    matches = find_sms_only_patterns_for_user(patterns, user.get("first_name", ""), user.get("last_name", ""), expected_number) if expected_number else name_matches
    return {
        "target_user": user.get("userid", clean_target),
        "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""),
        "expected_number": expected_number,
        "name_matches": name_matches,
        "matches": matches,
        "match_found": bool(matches),
    }


def create_sms_only_user(cucm_host, cucm_user, cucm_pass, target_user, ad_username="", ad_password=""):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = str(target_user or "").strip()
    filename = f"create_sms_only_user_{clean_target or 'unknown'}_{timestamp}.csv"
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Step", "Status", "Details"])
    if not clean_target:
        writer.writerow(["Validation", "Failed", "target_user is required"])
        return output.getvalue().encode("utf-8"), filename

    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)
    try:
        user = _get_user_details(session, cucm_host, clean_target)
        first_name = str(user.get("firstName", "") or "").strip()
        last_name = str(user.get("lastName", "") or "").strip()
        if not first_name or not last_name:
            raise RuntimeError("CUCM user must have both first and last name to build the SMS description.")
        writer.writerow(["Lookup User", "Success", f"Found {user.get('userid', clean_target)} ({first_name} {last_name})"])

        new_dn, selected_prefix = _choose_available_dn_auto(session, cucm_host)
        new_dn = str(new_dn or "").strip()
        if not re.fullmatch(r"\d{10}", new_dn):
            raise RuntimeError(f"Selected directory number must be exactly 10 digits; got '{new_dn}'.")
        writer.writerow(["Select Available DN", "Success", f"Selected {new_dn}/{DN_ROUTE_PARTITION} using auto-prefix {selected_prefix}"])

        _remove_line(session, cucm_host, new_dn, DN_ROUTE_PARTITION)
        writer.writerow(["Delete Inactive Line", "Success", f"Deleted {new_dn}/{DN_ROUTE_PARTITION} before translation-pattern creation"])

        description = build_sms_description(first_name, last_name, new_dn)
        _add_translation_pattern(session, cucm_host, new_dn, description, SMS_TEMPLATE_FIELDS)
        writer.writerow(["Add SMS Translation Pattern", "Success", f"Created {new_dn}/{SMS_ROUTE_PARTITION}; description='{description}'; callingSearchSpaceName={SMS_CALLING_SEARCH_SPACE}; calledPartyTransformationMask={SMS_CALLED_PARTY_TRANSFORM_MASK}"])

        ad_context = None
        if str(ad_username or "").strip() and ad_password:
            ad_context = {"username": str(ad_username).strip(), "password": ad_password}
        ad_ok, ad_message = update_ad_phone_fields(user.get("userid", clean_target), new_dn, ad_context)
        writer.writerow(["Update AD Phone Fields", "Success" if ad_ok else "Failed", ad_message])
    except Exception as exc:
        writer.writerow(["Script", "Error", str(exc)])
    return output.getvalue().encode("utf-8"), filename


def remove_sms_only_user(cucm_host, cucm_user, cucm_pass, target_user, read_sql, candidate=None):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = str(target_user or "").strip()
    filename = f"separate_sms_only_user_{clean_target or 'unknown'}_{timestamp}.csv"
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Step", "Status", "Details"])
    try:
        candidate = candidate or lookup_sms_only_user(cucm_host, cucm_user, cucm_pass, clean_target, read_sql)
        if candidate.get("lookup_error"):
            raise RuntimeError(candidate["lookup_error"])
        writer.writerow(["Lookup SMS User", "Success", f"{candidate['target_user']} ({candidate['first_name']} {candidate['last_name']})"])
        matches = candidate["matches"]
        if not matches and len(candidate.get("name_matches", [])) == 1:
            matches = candidate["name_matches"]
        if not matches:
            writer.writerow(["Find SMS Translation Pattern", "Skipped", "No exact SMS pattern matched the user's name, 10-digit pattern, partition, and transform mask."])
            return output.getvalue().encode("utf-8"), filename
        if not candidate.get("expected_number") and len(matches) > 1:
            writer.writerow(["Find SMS Translation Pattern", "Failed", "Multiple same-name SMS patterns were found and CUCM returned no telephone/primary extension to disambiguate them; no pattern was changed."])
            return output.getvalue().encode("utf-8"), filename

        session = requests.Session()
        session.verify = False
        session.trust_env = False
        session.auth = HTTPBasicAuth(cucm_user, cucm_pass)
        current_patterns = list_sms_only_patterns(cucm_host, cucm_user, cucm_pass, read_sql)
        current_name_matches = find_sms_only_patterns_for_user(
            current_patterns, candidate["first_name"], candidate["last_name"],
        )
        current_matches = find_sms_only_patterns_for_user(
            current_patterns, candidate["first_name"], candidate["last_name"], candidate.get("expected_number", ""),
        )
        if not current_matches and len(current_name_matches) == 1:
            current_matches = current_name_matches
        current_by_key = {(row["pattern"], row["route_partition"].casefold(), row["description"]): row for row in current_matches}
        for match in matches:
            key = (match["pattern"], match["route_partition"].casefold(), match["description"])
            if key not in current_by_key:
                writer.writerow(["Revalidate SMS Translation Pattern", "Failed", f"{match['pattern']}/{match['route_partition']} changed or is no longer an exact match; left untouched."])
                continue
            try:
                _remove_translation_pattern(session, cucm_host, match["pattern"], SMS_ROUTE_PARTITION)
                writer.writerow(["Delete SMS Translation Pattern", "Success", f"Deleted {match['pattern']}/{SMS_ROUTE_PARTITION}; {match['description']}"])
                _add_inactive_directory_number(session, cucm_host, match["pattern"])
                writer.writerow(["Rebuild Inactive Directory Number", "Success", f"Rebuilt {match['pattern']}/{DN_ROUTE_PARTITION} as inactive and reusable"])
            except Exception as exc:
                writer.writerow(["Separate SMS Translation Pattern", "Failed", f"{match['pattern']}/{SMS_ROUTE_PARTITION}: {exc}"])
    except Exception as exc:
        writer.writerow(["Script", "Error", str(exc)])
    return output.getvalue().encode("utf-8"), filename

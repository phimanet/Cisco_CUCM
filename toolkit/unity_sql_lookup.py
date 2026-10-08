import re


class UnitySqlError(RuntimeError):
    pass


RESULT_COLUMNS = ("owner_name", "primary_extension", "matched_field", "matched_number", "setting")
MAX_ROWS = 500


def lookup_queries(number, mode="exact"):
    number = str(number or "").strip()
    if not re.fullmatch(r"[0-9]{3,15}", number):
        raise ValueError("Enter 3-15 digits only; stored dialing prefixes are preserved.")
    if mode not in {"exact", "contains"}:
        raise ValueError("Choose Exact or Contains.")
    def match(field):
        return field + ("='" + number + "'" if mode == "exact" else " like '%" + number + "%'")
    return [
        ("Mailbox caller input", "select first 501 s.displayname as owner_name,s.dtmfaccessid as primary_extension,'TransferNumber' as matched_field,a.transfernumber as matched_number,a.touchtonekey as setting from vw_alternatecontactnumber_subscriber a join vw_subscriberbasic s on s.objectid=a.subscriberobjectid where " + match("a.transfernumber")),
        ("User/handler transfer rule", "select first 501 coalesce(s.displayname,h.displayname) as owner_name,coalesce(s.dtmfaccessid,h.dtmfaccessid) as primary_extension,'Extension' as matched_field,t.extension as matched_number,t.transferoptiontype as setting from vw_transferoptiondisplay t join vw_callhandler h on h.objectid=t.callhandlerobjectid left join vw_subscriberbasic s on s.callhandlerobjectid=h.objectid where " + match("t.extension")),
        ("Mailbox primary extension", "select first 501 s.displayname as owner_name,s.dtmfaccessid as primary_extension,'DtmfAccessId' as matched_field,s.dtmfaccessid as matched_number,'Primary' as setting from vw_subscriberbasic s where " + match("s.dtmfaccessid")),
        ("Handler primary extension", "select first 501 coalesce(s.displayname,h.displayname) as owner_name,coalesce(s.dtmfaccessid,h.dtmfaccessid) as primary_extension,'DtmfAccessId' as matched_field,h.dtmfaccessid as matched_number,'Primary' as setting from vw_callhandler h left join vw_subscriberbasic s on s.callhandlerobjectid=h.objectid where " + match("h.dtmfaccessid")),
    ]


def parse_cli_rows(output):
    lines = output.replace("\r", "").split("\n")
    if any(re.match(r"\s*(?:SQL (?:error|state)|error\s*:|syntax error|permission denied|command failed)", line, re.I) for line in lines):
        raise UnitySqlError("Unity CLI returned an error; lookup is incomplete.")
    for index, line in enumerate(lines):
        if index == 0 or not re.fullmatch(r"\s*-+(?:\s+-+)*\s*", line):
            continue
        spans = list(re.finditer(r"-+", line))
        if len(spans) != len(RESULT_COLUMNS) or tuple(lines[index - 1].split()) != RESULT_COLUMNS:
            continue
        rows = []
        for data in lines[index + 1:]:
            if not data.strip() or data.strip() == "admin:" or data.strip().startswith("admin:run cuc dbquery"):
                continue
            values = [data[span.start():spans[position + 1].start() if position + 1 < len(spans) else None].strip() for position, span in enumerate(spans)]
            values = ["" if value.lower() == "null" else value for value in values]
            if not values[0] or not values[3] or values[2] not in {"TransferNumber", "Extension", "DtmfAccessId"}:
                raise UnitySqlError("Unity CLI output is wrapped or incomplete; it was not treated as empty.")
            rows.append(dict(zip(RESULT_COLUMNS, values)))
        if len(rows) > MAX_ROWS:
            raise UnitySqlError("More than 500 rows match; narrow the search.")
        return rows
    if re.fullmatch(r"\s*(?:No (?:records|rows)(?: found)?|0 rows(?: returned)?)\.?\s*", output, re.I):
        return []
    raise UnitySqlError("Expected Unity SQL result columns were not returned; no-match status is unverified.")


def command_templates(number, mode="exact"):
    return [(label, "run cuc dbquery unitydirdb " + query) for label, query in lookup_queries(number, mode)]
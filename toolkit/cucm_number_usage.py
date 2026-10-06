import re
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth

from toolkit.route_plan_report import _soap_execute_sql, _strip_ns


PAGE_SIZE = 500
MAX_PAGES = 2000
TABLES = ("numplan", "callforwarddynamic", "devicenumplanmap", "remotedestination", "enduser")


def _digits(value):
    return re.sub(r"[^0-9]", "", str(value or ""))


def _number(value):
    text = str(value or "").strip()
    if not re.fullmatch(r"[+0-9(). \-]+", text):
        raise ValueError("Enter a telephone number using digits and optional +, spaces, parentheses or hyphens.")
    digits = _digits(text)
    if not 4 <= len(digits) <= 15:
        raise ValueError("Enter 4 to 15 digits; matching uses number contains.")
    return digits


def _matches(value, number):
    text = str(value or "").strip()
    separators = r"[+(). \-\\]*"
    return bool(re.search(separators.join(number), text))


def _candidate_where(alias, fields, number):
    candidate = "%" + "%".join(number) + "%"
    return " OR ".join(f"{alias}.{field} LIKE '{candidate}'" for field in fields)


def _execute(session, host, sql):
    response = session.post(
        f"https://{host}:8443/axl/", data=_soap_execute_sql(sql).encode("utf-8"),
        headers={"Content-Type": "text/xml"}, timeout=30, verify=False,
    )
    if response.status_code != 200:
        raise RuntimeError(f"CUCM SQL read failed (HTTP {response.status_code}).")
    root = ET.fromstring(response.text)
    for element in root.iter():
        if _strip_ns(element.tag).lower() in ("fault", "axlerror", "error"):
            raise RuntimeError("CUCM SQL read failed: " + " ".join(element.itertext()).strip()[:600])
    if not any(_strip_ns(element.tag) == "executeSQLQueryResponse" for element in root.iter()):
        raise RuntimeError("Unexpected CUCM SQL response; lookup is incomplete.")
    return [
        {_strip_ns(child.tag).lower(): (child.text or "").strip() for child in element}
        for element in root.iter() if _strip_ns(element.tag) == "row"
    ]


def _pages(session, host, select, tail):
    for page in range(MAX_PAGES):
        rows = _execute(session, host, f"SELECT SKIP {page * PAGE_SIZE} FIRST {PAGE_SIZE} {select} {tail}")
        yield from rows
        if len(rows) < PAGE_SIZE:
            return
    raise RuntimeError("CUCM scan exceeded its page limit; lookup is incomplete.")


def lookup_number_usage(cucm_host, cucm_user, cucm_pass, number):
    query = _number(number)
    results = []
    checked_fields = []
    warnings = []
    with requests.Session() as session:
        session.verify = False
        session.trust_env = False
        session.auth = HTTPBasicAuth(cucm_user, cucm_pass)
        schema = list(_pages(
            session, cucm_host,
            "t.tabname AS table_name, c.colname AS column_name",
            "FROM systables t JOIN syscolumns c ON c.tabid = t.tabid "
            "WHERE t.tabname IN ('numplan','callforwarddynamic','devicenumplanmap','remotedestination','enduser') ORDER BY t.tabname, c.colno",
        ))
        columns = {table: set() for table in TABLES}
        for row in schema:
            table = row.get("table_name", "").lower()
            column = row.get("column_name", "").lower()
            if table in columns and re.fullmatch(r"[a-z][a-z0-9_]*", column):
                columns[table].add(column)
        forwarding = sorted(column for column in columns["numplan"] if column.startswith("cf") and "destination" in column)
        if not forwarding or not {"pkid", "fknumplan", "cfadestination"}.issubset(columns["callforwarddynamic"]):
            raise RuntimeError("Required CUCM forwarding schema is unavailable; lookup is incomplete.")
        pattern_fields = sorted(column for column in columns["numplan"] if column == "dnorpattern" or "mask" in column or column.endswith("prefixdigits"))
        if not {"dnorpattern", "calledpartytransformationmask", "callingpartytransformationmask"}.issubset(pattern_fields):
            raise RuntimeError("Required CUCM pattern/mask schema is unavailable; lookup is incomplete.")
        line_ids = set()
        scans = [
            ("numplan", "n", forwarding + pattern_fields, "", "n.pkid", ""),
            ("callforwarddynamic", "cf", ["cfadestination"], "JOIN callforwarddynamic cf ON cf.fknumplan = n.pkid ", "cf.pkid", ""),
        ]
        if {"pkid", "fknumplan", "fkdevice", "e164mask"}.issubset(columns["devicenumplanmap"]):
            scans.append((
                "devicenumplanmap", "dm", ["e164mask"],
                "JOIN devicenumplanmap dm ON dm.fknumplan = n.pkid JOIN device d ON d.pkid = dm.fkdevice ",
                "dm.pkid", ", d.name AS device_name",
            ))
        else:
            warnings.append("External Phone Number Masks were not checked: schema unavailable.")
        for table, alias, fields, joins, order, extra in scans:
            checked_fields.extend(f"{table}.{field}" for field in fields)
            select = (
                f"{order} AS object_id, n.pkid AS line_id, n.dnorpattern AS pattern, n.description AS description, "
                "rp.name AS route_partition, n.tkpatternusage AS pattern_usage"
                + extra + ", " + ", ".join(f"{alias}.{field} AS value_{index}" for index, field in enumerate(fields))
            )
            where = _candidate_where(alias, fields, query)
            tail = "FROM numplan n " + joins + "LEFT JOIN routepartition rp ON rp.pkid = n.fkroutepartition " + f"WHERE {where} ORDER BY {order}"
            for row in _pages(session, cucm_host, select, tail):
                for index, field in enumerate(fields):
                    value = row.get(f"value_{index}", "")
                    if not _matches(value, query):
                        continue
                    line_ids.add(row["line_id"])
                    category = "Forwarding" if field in forwarding or field == "cfadestination" else "Pattern / Transform Mask"
                    if field == "e164mask":
                        category = "External Phone Number Mask"
                    results.append({
                        "object_id": row["object_id"], "line_id": row["line_id"], "pattern": row.get("pattern", ""),
                        "route_partition": row.get("route_partition", "") or "<None>",
                        "description": row.get("description", ""), "pattern_usage": row.get("pattern_usage", ""),
                        "field": f"{table}.{field}", "destination": value, "category": category,
                        "devices": [row["device_name"]] if row.get("device_name") else [],
                    })
        for table, identity, fields, category in (
            ("remotedestination", "name", ["destination"], "Remote Destination"),
            ("enduser", "userid", ["telephonenumber"], "End User Telephone Number"),
        ):
            if not {"pkid", identity, *fields}.issubset(columns[table]):
                warnings.append(f"{category} was not checked: schema unavailable.")
                continue
            checked_fields.extend(f"{table}.{field}" for field in fields)
            select = f"pkid AS object_id, {identity} AS pattern, " + ", ".join(fields)
            where = _candidate_where(table, fields, query)
            for row in _pages(session, cucm_host, select, f"FROM {table} WHERE {where} ORDER BY pkid"):
                for field in fields:
                    if _matches(row.get(field), query):
                        results.append({
                            "object_id": row["object_id"], "pattern": row.get("pattern", ""), "route_partition": "",
                            "description": "", "pattern_usage": "", "field": f"{table}.{field}",
                            "destination": row[field], "category": category, "devices": [],
                        })
        devices = {}
        ordered_ids = sorted(line_ids)
        for offset in range(0, len(ordered_ids), 100):
            literals = ",".join("'" + object_id.replace("'", "''") + "'" for object_id in ordered_ids[offset:offset + 100])
            for row in _pages(
                session, cucm_host, "dm.fknumplan AS object_id, d.name AS device_name",
                "FROM devicenumplanmap dm JOIN device d ON d.pkid = dm.fkdevice "
                + f"WHERE dm.fknumplan IN ({literals}) ORDER BY dm.pkid",
            ):
                devices.setdefault(row["object_id"], set()).add(row.get("device_name", ""))
        for row in results:
            if row.get("line_id") and row["category"] != "External Phone Number Mask":
                row["devices"] = sorted(devices.get(row["line_id"], set()))
    results.sort(key=lambda row: (row["category"], row["pattern"], row["route_partition"], row["field"]))
    return {
        "query": query, "results": results, "total_matches": len(results),
        "mode": "focused", "status": "completed", "match_rule": "Contains digits (formatting ignored)",
        "forwarding_matches": sum(row["category"] == "Forwarding" for row in results),
        "checked_fields": checked_fields, "warnings": warnings,
        "scope_note": "Not deletion clearance. Wildcard routing/masks, other CUCM fields, Unity, applications, carrier/Sinch inventory and external systems are not checked.",
    }


DEEP_PAGE_SIZE = 100
DEEP_FIELDS_PER_TASK = 8
TEXT_TYPES = {0, 13, 15, 16, 40}
SCALAR_TYPES = {1, 2, 3, 4, 5, 6, 7, 8, 10, 14, 17, 18, 45, 52, 53}
SENSITIVE_FIELD = re.compile(r"password|passwd|secret|token|certificate|privatekey|publickey|credential", re.I)


def _deep_session(user, password):
    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(user, password)
    return session


def create_deep_scan(host, user, password, number):
    query = _number(number)
    with _deep_session(user, password) as session:
        schema = list(_pages(
            session, host,
            "t.tabname AS table_name, c.colname AS column_name, c.coltype AS column_type",
            "FROM systables t JOIN syscolumns c ON c.tabid = t.tabid "
            "WHERE t.tabid >= 100 AND t.tabtype = 'T' ORDER BY t.tabname, c.colno",
        ))
    if not schema:
        raise RuntimeError("CUCM returned no user-table schema; deep scan cannot start.")
    tables = {}
    skipped = []
    for row in schema:
        table = row.get("table_name", "").lower()
        column = row.get("column_name", "").lower()
        field = f"{table}.{column}"
        if not re.fullmatch(r"[a-z][a-z0-9_]*", table) or not re.fullmatch(r"[a-z][a-z0-9_]*", column):
            skipped.append({"field": field, "reason": "Unsupported identifier"})
            continue
        try:
            column_type = int(row["column_type"]) % 256
        except (KeyError, ValueError, TypeError):
            skipped.append({"field": field, "reason": "Unknown data type"})
            continue
        entry = tables.setdefault(table, {"fields": [], "columns": set()})
        entry["columns"].add(column)
        if SENSITIVE_FIELD.search(table + "." + column):
            skipped.append({"field": field, "reason": "Sensitive credential/certificate field excluded"})
        elif column_type not in TEXT_TYPES | SCALAR_TYPES:
            skipped.append({"field": field, "reason": f"Unsupported binary/large-object/data type {column_type}"})
        else:
            entry["fields"].append({"name": column, "text": column_type in TEXT_TYPES})
    tasks = []
    for table, entry in sorted(tables.items()):
        identity = "pkid" if "pkid" in entry["columns"] else ""
        display = next((name for name in ("dnorpattern", "name", "userid") if name in entry["columns"]), "")
        for offset in range(0, len(entry["fields"]), DEEP_FIELDS_PER_TASK):
            tasks.append({"table": table, "identity": identity, "display": display, "fields": entry["fields"][offset:offset + DEEP_FIELDS_PER_TASK]})
    if not tasks:
        raise RuntimeError("No searchable CUCM scalar fields were discovered.")
    return {
        "query": query, "mode": "deep", "status": "paused", "match_rule": "Contains digits (formatting ignored)",
        "tasks": tasks, "task_index": 0, "page_offset": 0, "results": [], "total_matches": 0,
        "forwarding_matches": 0, "checked_fields": [], "skipped_fields": skipped, "failures": [],
        "warnings": ["Database contents may change while the scan runs; review current configuration before deletion."],
        "scope_note": "Read-only user-table scalar-field search, not deletion clearance. System catalogs/views, sensitive and unsupported fields are excluded. Wildcard-derived uses, Unity, Sinch and external applications are not checked.",
    }


def advance_deep_scan(state, host, user, password):
    if state.get("status") == "completed":
        return
    index = state["task_index"]
    task = state["tasks"][index]
    table = task["table"]
    fields = task["fields"]
    expressions = [f"t.{field['name']}" if field["text"] else f"CAST(t.{field['name']} AS VARCHAR(64))" for field in fields]
    select = [f"{expression} AS value_{field_index}" for field_index, expression in enumerate(expressions)]
    if task["identity"]:
        select.append(f"t.{task['identity']} AS object_id")
    if task["display"]:
        select.append(f"t.{task['display']} AS object_name")
    candidate = "%" + "%".join(state["query"]) + "%"
    where = " OR ".join(f"{expression} LIKE '{candidate}'" for expression in expressions)
    order = "t." + task["identity"] if task["identity"] else ", ".join(f"value_{field_index}" for field_index in range(len(fields)))
    sql = f"SELECT SKIP {state['page_offset']} FIRST {DEEP_PAGE_SIZE} " + ", ".join(select) + f" FROM {table} t WHERE {where} ORDER BY {order}"
    try:
        with _deep_session(user, password) as session:
            rows = _execute(session, host, sql)
    except Exception as exc:
        state["failures"].append({"table": table, "fields": [field["name"] for field in fields], "offset": state["page_offset"], "error": str(exc)[:600]})
        rows = None
    if rows is not None:
        for ordinal, row in enumerate(rows, state["page_offset"]):
            for field_index, field in enumerate(fields):
                value = row.get(f"value_{field_index}", "")
                if not _matches(value, state["query"]):
                    continue
                state["results"].append({
                    "category": "Database Reference", "pattern": row.get("object_name", ""), "route_partition": "",
                    "field": f"{table}.{field['name']}", "destination": value,
                    "object_id": row.get("object_id", "") or f"Row {ordinal + 1} (no PKID)",
                    "devices": [], "description": "", "pattern_usage": "", "table": table,
                })
        if len(rows) == DEEP_PAGE_SIZE:
            state["page_offset"] += DEEP_PAGE_SIZE
            if state["page_offset"] >= PAGE_SIZE * MAX_PAGES:
                state["failures"].append({"table": table, "fields": [field["name"] for field in fields], "error": "Page limit reached; field coverage is incomplete."})
            else:
                state["status"] = "paused"
                state["total_matches"] = len(state["results"])
                return
        else:
            state["checked_fields"].extend(f"{table}.{field['name']}" for field in fields)
    state["task_index"] += 1
    state["page_offset"] = 0
    state["total_matches"] = len(state["results"])
    state["status"] = "completed" if state["task_index"] == len(state["tasks"]) else "paused"
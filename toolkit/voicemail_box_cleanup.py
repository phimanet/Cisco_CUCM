import csv
import hashlib
import io
import os
import uuid

import requests

from toolkit import unity_number_search as storage
from toolkit import unity_user_extract as users


PAGE_SIZE = 500
MAX_PAGES = 2000
LIMITATIONS = "Exact primary-extension match on all CSF/TCT/BOT/TAB device lines in the selected CUCM, across all partitions. A match does not verify mailbox ownership, registration or use. No match is a review candidate, not deletion clearance; other phones and voicemail-only users may be legitimate. No changes are performed."
RETENTION = "Latest scan and latest completed report per Unity/CUCM pair only, not a history archive. Browser-driven: closing the page stops further reads; View Latest Scan and Resume continues saved progress with current credentials. Normal restarts and code pulls preserve data; runtime deletion or older data/VM restores do not."
COLUMNS = (("First Name", "first_name"), ("Last Name", "last_name"), ("Email", "email"),
           ("Username", "username"), ("Extension", "extension"), ("Jabber Match", "jabber_match"),
           ("Jabber Devices", "jabber_devices"), ("Partitions", "partitions"))


def pair_root(root, cucm_host):
    return os.path.join(root, hashlib.sha256(storage.normalize_host(cucm_host).encode()).hexdigest())


def load(root, host, cucm_host, kind="scan"):
    state = storage.load(pair_root(root, cucm_host), host, kind)
    if state.get("purpose") != "voicemail_box_cleanup" or state.get("cucm_host") != storage.normalize_host(cucm_host):
        raise ValueError("Saved cleanup belongs to another environment or is invalid.")
    return state


def save(root, state, kind="scan"):
    storage.save(pair_root(root, state["cucm_host"]), state, kind)


def start(host, cucm_host, cucm_user, cucm_pass, sql_executor):
    index = {}
    seen = set()
    for page in range(MAX_PAGES):
        sql = (
            f"SELECT SKIP {page * PAGE_SIZE} FIRST {PAGE_SIZE} "
            "d.pkid AS device_id, n.pkid AS line_id, d.name AS device_name, "
            "n.dnorpattern AS extension, COALESCE(r.name, '') AS partition "
            "FROM device d INNER JOIN devicenumplanmap dm ON dm.fkdevice = d.pkid "
            "INNER JOIN numplan n ON n.pkid = dm.fknumplan "
            "LEFT OUTER JOIN routepartition r ON r.pkid = n.fkroutepartition "
            "WHERE (UPPER(d.name) LIKE 'CSF%' OR UPPER(d.name) LIKE 'TCT%' OR UPPER(d.name) LIKE 'BOT%' OR UPPER(d.name) LIKE 'TAB%') "
            "ORDER BY d.pkid, n.pkid"
        )
        batch = sql_executor(cucm_host, cucm_user, cucm_pass, sql)
        if not isinstance(batch, list):
            raise ValueError("CUCM Jabber inventory was not returned.")
        for row in batch:
            device = str(row.get("device_name", "") or "").strip()
            extension = str(row.get("extension", "") or "").strip()
            partition = str(row.get("partition", "") or "").strip()
            if not device.upper().startswith(("CSF", "TCT", "BOT", "TAB")) or not extension:
                raise ValueError("CUCM returned an invalid Jabber inventory row.")
            key = (device, extension, partition)
            if key in seen:
                raise ValueError("CUCM repeated a Jabber inventory row; refresh refused.")
            seen.add(key)
            index.setdefault(extension, []).append({"device": device, "partition": partition})
        if len(batch) < PAGE_SIZE:
            break
    else:
        raise ValueError("CUCM Jabber inventory exceeded the safe page limit.")
    now = storage.timestamp()
    return dict(schema_version=1, purpose="voicemail_box_cleanup", host=storage.normalize_host(host),
                cucm_host=storage.normalize_host(cucm_host), job_id=uuid.uuid4().hex, status="running",
                started_at=now, updated_at=now, jabber_checked_at=now, jabber_index=index,
                page=0, total=None, seen_ids=[], rows=[], requests=0, tasks=[], fields=[], edges=[],
                coverage=[], excluded_links=[], scheduled=[], failures=[], limitations=LIMITATIONS, retention=RETENTION)


def advance(state, username, password, client=None):
    if state["status"] != "running":
        return
    if not username or not password:
        raise ValueError("Current Unity credentials are required to resume.")
    if state["page"] >= MAX_PAGES:
        raise ValueError("Unity user inventory exceeded the safe page limit.")
    client = client or requests
    payload = users._read_user_resource(client, state["host"], username, password, "/vmrest/users",
                                        {"rowsPerPage": PAGE_SIZE, "pageNumber": state["page"]})
    try:
        records, total = storage._records(payload)
    except storage.UnityCountOnlyPage as exc:
        if state["page"] != 0:
            raise ValueError("Unity returned a count without records after page 0.") from None
        state.update(page=1, total=exc.total, requests=state["requests"] + 1, updated_at=storage.timestamp())
        return
    if total is not None and state["total"] is not None and total != state["total"]:
        raise ValueError("Unity inventory count changed during the scan; start a fresh scan.")
    expected = state["total"] if total is None else total
    seen = set(state["seen_ids"])
    rows = []
    for record in records:
        person = users._person_identity(record)
        if person["object_id"] in seen:
            raise ValueError("Unity repeated a user/page; incomplete scan was not accepted.")
        seen.add(person["object_id"])
        matches = state["jabber_index"].get(person["extension"], []) if person["extension"] else []
        rows.append({"object_id": person["object_id"], "first_name": person["first_name"],
                     "last_name": person["last_name"], "email": person["email"], "username": person["alias"],
                     "extension": person["extension"],
                     "jabber_match": "Matching Jabber" if matches else "No matching Jabber" if person["extension"] else "No primary extension",
                     "jabber_devices": "; ".join(sorted({item["device"] for item in matches})),
                     "partitions": "; ".join(sorted({item["partition"] or "<None>" for item in matches}))})
    count = len(state["rows"]) + len(rows)
    if expected is not None and (count > expected or (not records and count < expected)):
        raise ValueError("Unity pagination is incomplete or inconsistent; prior report retained.")
    complete = count == expected if expected is not None else len(records) < PAGE_SIZE
    if not records and expected is None:
        raise ValueError("Unity returned an empty page without an authoritative total.")
    state["rows"].extend(rows)
    state.update(seen_ids=sorted(seen), total=expected, page=state["page"] + 1,
                 requests=state["requests"] + 1, status="completed" if complete else "running", updated_at=storage.timestamp())


def report(state):
    keys = ("schema_version", "purpose", "host", "cucm_host", "job_id", "status", "started_at", "updated_at",
            "jabber_checked_at", "rows", "total", "requests", "coverage", "failures", "excluded_links", "limitations", "retention")
    return {key: state[key] for key in keys}


def csv_report(value):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    columns = COLUMNS + (("Unity Host", "host"), ("CUCM Host", "cucm_host"), ("Report Status", "status"),
                         ("Jabber Checked At", "jabber_checked_at"), ("Unity Updated At", "updated_at"), ("Limitations", "limitations"))
    writer.writerow([label for label, _ in columns])
    for row in value["rows"]:
        values = []
        for _, key in columns:
            text = str(row.get(key, value.get(key, "")) or "")
            values.append("'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text)
        writer.writerow(values)
    return stream.getvalue()
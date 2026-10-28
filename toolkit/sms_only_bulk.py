import copy
import csv
import datetime
import io
import json
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

try:
    from . import sms_only_user
    from .ad_phone_fields import update_ad_phone_fields
    from .create_teams_telephony_user import DN_ROUTE_PARTITION, _remove_line, _add_translation_pattern
    from .remove_teams_telephony_user import _add_inactive_directory_number
except ImportError:
    import sms_only_user
    from ad_phone_fields import update_ad_phone_fields
    from create_teams_telephony_user import DN_ROUTE_PARTITION, _remove_line, _add_translation_pattern
    from remove_teams_telephony_user import _add_inactive_directory_number

MAX_BULK_ROWS = 500
SQL_BATCH_SIZE = 100
SQL_PAGE_SIZE = 1000
SQL_MAX_PAGES = 20
ACTIVE_JOB_STATES = {"needs_check", "checking", "awaiting_confirmation", "queued", "running", "paused", "credentials_required", "check_failed"}
TERMINAL_JOB_STATES = {"completed", "cancelled", "no_available_rows"}
TERMINAL_ROW_STATES = {"invalid", "duplicate", "completed", "needs_review", "cancelled", "built"}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _sql_quote(value):
    return "'" + str(value or "").replace("'", "''") + "'"


def parse_sms_bulk_rows(raw_text):
    source = str(raw_text or "")
    delimiter = "\t" if "\t" in source and "," not in source else ","
    parsed = list(csv.reader(io.StringIO(source), delimiter=delimiter))
    rows = []
    seen_emails = set()
    seen_numbers = set()
    for input_line, values in enumerate(parsed, start=1):
        fields = [str(value or "").strip() for value in values]
        if not fields or not any(fields):
            continue
        if len(fields) == 1:
            fields = fields[0].split()
        if input_line == 1 and len(fields) >= 2 and fields[0].casefold() in {"email", "email address"} and fields[1].casefold() in {"number", "phone", "extension", "sms number"}:
            continue
        email = fields[0] if fields else ""
        number = fields[1] if len(fields) > 1 else ""
        row = {
            "row_id": str(len(rows) + 1),
            "input_line": input_line,
            "email": email,
            "number": number,
            "status": "pending",
            "detail": "",
            "userid": "",
            "first_name": "",
            "last_name": "",
            "description": "",
            "ldap_status": "Not attempted",
            "pattern_status": "Not attempted",
        }
        if len(fields) != 2:
            row.update(status="invalid", detail="Enter exactly two fields: email and 10-digit number.")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            row.update(status="invalid", detail="Invalid email address.")
        elif not re.fullmatch(r"\d{10}", number):
            row.update(status="invalid", detail="Number must be exactly 10 digits.")
        else:
            email_key = email.casefold()
            if email_key in seen_emails:
                row.update(status="duplicate", detail="Duplicate email in this submission.")
            elif number in seen_numbers:
                row.update(status="duplicate", detail="Duplicate number in this submission.")
            else:
                seen_emails.add(email_key)
                seen_numbers.add(number)
        rows.append(row)
        if len(rows) > MAX_BULK_ROWS:
            raise ValueError(f"A submission is limited to {MAX_BULK_ROWS} rows.")
    if not rows:
        raise ValueError("Paste at least one email,10-digit-number row.")
    return rows


def _chunks(values, size):
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _normalized_false(value):
    return str(value or "").strip().casefold() in {"f", "false", "0", "no"}


def _number_inventory(numbers, cucm_host, cucm_user, cucm_pass, read_sql):
    found = {number: [] for number in numbers}
    for batch in _chunks(numbers, SQL_BATCH_SIZE):
        number_values = ",".join(_sql_quote(number) for number in batch)
        where_clause = (
            f"r.name={_sql_quote(sms_only_user.SMS_ROUTE_PARTITION)} "
            f"AND n.dnorpattern IN ({number_values})"
        )
        page_found = False
        for page_number in range(SQL_MAX_PAGES):
            offset = page_number * SQL_PAGE_SIZE
            sql = (
                f"SELECT SKIP {offset} FIRST {SQL_PAGE_SIZE} n.dnorpattern AS pattern, "
                "r.name AS route_partition, n.tkpatternusage AS pattern_usage, "
                "n.iscallable AS iscallable, m.fkdevice AS associated_device "
                "FROM numplan n JOIN routepartition r ON r.pkid=n.fkroutepartition "
                "LEFT JOIN devicenumplanmap m ON m.fknumplan=n.pkid "
                f"WHERE {where_clause} "
                "ORDER BY n.dnorpattern, n.tkpatternusage, m.fkdevice"
            )
            page = read_sql(cucm_host, cucm_user, cucm_pass, sql)
            if not isinstance(page, list) or len(page) > SQL_PAGE_SIZE:
                raise RuntimeError("CUCM number availability query returned invalid data.")
            for record in page:
                if not isinstance(record, dict):
                    raise RuntimeError("CUCM number availability query returned an invalid row.")
                pattern = str(record.get("pattern", "") or "").strip()
                if pattern not in found:
                    raise RuntimeError("CUCM number availability query returned an unexpected number.")
                found[pattern].append(record)
            if len(page) < SQL_PAGE_SIZE:
                page_found = True
                break
        if not page_found:
            raise RuntimeError("CUCM number availability query exceeded its safe page limit.")
    aggregated = {}
    for number, entries in found.items():
        grouped = {}
        for entry in entries:
            key = (
                str(entry.get("pattern", "") or "").strip(),
                str(entry.get("route_partition", "") or "").strip(),
                str(entry.get("pattern_usage", "") or "").strip(),
                str(entry.get("iscallable", "") or "").strip(),
            )
            current = grouped.setdefault(key, {"associated_devices": set()})
            associated_device = str(entry.get("associated_device", "") or "").strip()
            if associated_device:
                current["associated_devices"].add(associated_device)
        aggregated[number] = [
            {"pattern": key[0], "route_partition": key[1], "pattern_usage": key[2], "iscallable": key[3], "device_count": len(value["associated_devices"])}
            for key, value in grouped.items()
        ]
    return aggregated


def precheck_sms_bulk_rows(rows, cucm_host, cucm_user, cucm_pass, read_sql):
    checked = {str(row["row_id"]): dict(row) for row in rows}
    pending = [row for row in rows if row.get("status") in {"pending", "available", "number_not_available", "user_not_found", "ambiguous_email", "already_assigned", "lookup_failed"}]
    if not pending:
        return checked

    users_by_email = {}
    email_set = sorted({row["email"].casefold() for row in pending})
    try:
        for email_batch in _chunks(email_set, SQL_BATCH_SIZE):
            values = ",".join(_sql_quote(email) for email in email_batch)
            sql = (
                "SELECT userid AS userid, firstname AS first_name, lastname AS last_name, mailid AS email "
                "FROM enduser WHERE LOWER(mailid) IN (" + values + ") ORDER BY LOWER(mailid), userid"
            )
            for user in read_sql(cucm_host, cucm_user, cucm_pass, sql):
                if not isinstance(user, dict):
                    raise RuntimeError("CUCM email lookup returned an invalid row.")
                email = str(user.get("email", "") or "").strip().casefold()
                if email in email_set:
                    users_by_email.setdefault(email, []).append(user)
    except Exception as exc:
        for row in pending:
            checked[str(row["row_id"])].update(status="lookup_failed", detail=f"CUCM email lookup failed: {exc}")
        return checked

    numbers = sorted({row["number"] for row in pending})
    try:
        number_rows = _number_inventory(numbers, cucm_host, cucm_user, cucm_pass, read_sql)
        sms_patterns = sms_only_user.list_sms_only_patterns(cucm_host, cucm_user, cucm_pass, read_sql)
    except Exception as exc:
        for row in pending:
            checked[str(row["row_id"])].update(status="lookup_failed", detail=f"Read-only CUCM precheck failed: {exc}")
        return checked

    for row in pending:
        output = checked[str(row["row_id"])]
        user_matches = users_by_email.get(row["email"].casefold(), [])
        if not user_matches:
            output.update(status="user_not_found", detail="No CUCM end user has this exact email address.")
            continue
        if len(user_matches) != 1:
            output.update(status="ambiguous_email", detail=f"Email matched {len(user_matches)} CUCM users; no changes made.")
            continue
        user = user_matches[0]
        userid = str(user.get("userid", "") or "").strip()
        first_name = str(user.get("first_name", "") or "").strip()
        last_name = str(user.get("last_name", "") or "").strip()
        if not userid or not first_name or not last_name:
            output.update(status="lookup_failed", detail="CUCM user is missing user ID, first name, or last name.")
            continue
        existing_sms = sms_only_user.find_sms_only_patterns_for_user(sms_patterns, first_name, last_name)
        if existing_sms:
            output.update(status="already_assigned", userid=userid, first_name=first_name, last_name=last_name, detail="User already has an SMS - translation pattern: " + ", ".join(item["pattern"] for item in existing_sms))
            continue

        entries = number_rows.get(row["number"], [])
        device_patterns = [entry for entry in entries if str(entry.get("pattern_usage", "") or "").strip() == "2"]
        translation_patterns = [entry for entry in entries if str(entry.get("pattern_usage", "") or "").strip() in {"3", "15"}]
        available_line = None
        if len(device_patterns) == 1:
            line = device_patterns[0]
            try:
                device_count = int(str(line.get("device_count", "0") or "0").strip())
            except (TypeError, ValueError):
                device_count = -1
            if (
                str(line.get("route_partition", "") or "").strip().casefold() == sms_only_user.SMS_ROUTE_PARTITION.casefold()
                and _normalized_false(line.get("iscallable"))
                and device_count == 0
            ):
                available_line = line
        if available_line is None or translation_patterns:
            details = "Number is not an unassigned inactive DN in ENT_DEVICE_PT."
            if translation_patterns:
                details = "A translation pattern already uses this number in ENT_DEVICE_PT."
            output.update(status="number_not_available", userid=userid, first_name=first_name, last_name=last_name, detail=details)
            continue
        description = sms_only_user.build_sms_description(first_name, last_name, row["number"])
        output.update(
            status="available",
            userid=userid,
            first_name=first_name,
            last_name=last_name,
            description=description,
            route_partition=sms_only_user.SMS_ROUTE_PARTITION,
            calling_search_space=sms_only_user.SMS_CALLING_SEARCH_SPACE,
            called_party_transform_mask=sms_only_user.SMS_CALLED_PARTY_TRANSFORM_MASK,
            detail="Exact CUCM email found; number is inactive, unassigned, and has no conflicting translation pattern.",
        )
    return checked


def build_sms_for_specific_number(cucm_host, cucm_user, cucm_pass, row):
    number = str(row.get("number", "") or "").strip()
    if not re.fullmatch(r"\d{10}", number):
        return {"status": "failed", "pattern_status": "Not attempted", "ldap_status": "Not attempted", "detail": "Number must be exactly 10 digits."}
    userid = str(row.get("userid", "") or "").strip()
    first_name = str(row.get("first_name", "") or "").strip()
    last_name = str(row.get("last_name", "") or "").strip()
    if not userid or not first_name or not last_name:
        return {"status": "failed", "pattern_status": "Not attempted", "ldap_status": "Not attempted", "detail": "Saved precheck is missing CUCM identity details."}

    session = requests.Session()
    session.verify = False
    session.trust_env = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)
    description = sms_only_user.build_sms_description(first_name, last_name, number)
    try:
        _remove_line(session, cucm_host, number, DN_ROUTE_PARTITION)
    except Exception as exc:
        return {"status": "failed", "pattern_status": "Not attempted", "ldap_status": "Not attempted", "detail": f"Could not delete the prechecked inactive line; no translation pattern was created: {exc}"}

    try:
        _add_translation_pattern(session, cucm_host, number, description, sms_only_user.SMS_TEMPLATE_FIELDS)
    except Exception as exc:
        try:
            _add_inactive_directory_number(session, cucm_host, number)
            recovery = "The inactive DN was restored."
        except Exception as restore_exc:
            recovery = f"Inactive DN restoration also failed: {restore_exc}"
        return {"status": "needs_review", "pattern_status": "Failed", "ldap_status": "Not attempted", "detail": f"Translation-pattern creation failed: {exc} {recovery}"}

    ad_ok, ad_message = update_ad_phone_fields(userid, number, {"username": cucm_user, "password": cucm_pass})
    if not ad_ok:
        return {"status": "needs_review", "pattern_status": "Created", "ldap_status": "Failed", "detail": f"Created {number} with description '{description}', but LDAP update failed: {ad_message}. Do not replay this row; correct LDAP separately."}
    return {
        "status": "built",
        "pattern_status": "Created",
        "ldap_status": "Updated",
        "description": description,
        "detail": f"Created {number}/{sms_only_user.SMS_ROUTE_PARTITION}; calledPartyTransformationMask={sms_only_user.SMS_CALLED_PARTY_TRANSFORM_MASK}; LDAP telephoneNumber/ipPhone updated from {number}.",
    }


def sms_bulk_csv(job):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Email", "10-Digit Number", "CUCM User ID", "Name", "Status", "Availability", "Description", "Partition", "Calling Search Space", "Called Party Transform Mask", "Pattern", "LDAP", "Details"])
    for row in job.get("rows", []):
        writer.writerow([
            row.get("email", ""), row.get("number", ""), row.get("userid", ""),
            " ".join(part for part in [row.get("first_name", ""), row.get("last_name", "")] if part),
            row.get("status", ""), row.get("availability", ""), row.get("description", ""),
            row.get("route_partition", ""), row.get("calling_search_space", ""),
            row.get("called_party_transform_mask", ""), row.get("pattern_status", ""),
            row.get("ldap_status", ""), row.get("detail", ""),
        ])
    return output.getvalue().encode("utf-8-sig")


class BulkSmsTranslationQueue:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.RLock()
        self.worker = None

    def _path(self, job_id):
        if not re.fullmatch(r"[a-f0-9]{32}", str(job_id or "")):
            raise ValueError("Invalid SMS bulk job ID.")
        return self.root / (job_id + ".json")

    def _read(self, path):
        with path.open(encoding="utf-8") as handle:
            job = json.load(handle)
        if job.get("version") != 1 or job.get("id") != path.stem or not isinstance(job.get("rows"), list):
            raise ValueError("Invalid saved SMS bulk state; restore runtime data before continuing.")
        return job

    def _save(self, job):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        job["updated_at"] = _now()
        descriptor, temporary = tempfile.mkstemp(dir=self.root, suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(job, handle, ensure_ascii=True)
                handle.flush()
                os.fsync(handle.fileno())
            for attempt in range(3):
                try:
                    os.replace(temporary, self._path(job["id"]))
                    break
                except PermissionError:
                    if os.name != "nt" or attempt == 2:
                        raise
                    time.sleep(0.05 * (attempt + 1))
            if os.name != "nt":
                directory_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def submit(self, host, operator, raw_text):
        rows = parse_sms_bulk_rows(raw_text)
        with self.lock:
            for path in self.root.glob("*.json"):
                existing = self._read(path)
                if existing.get("host") == host and existing.get("status") in ACTIVE_JOB_STATES:
                    raise ValueError("An unfinished SMS bulk job exists for this CUCM environment. Load or finish it first.")
            job = {
                "version": 1,
                "id": uuid.uuid4().hex,
                "host": host,
                "operator": operator,
                "created_at": _now(),
                "status": "needs_check",
                "reviewed_at": "",
                "error": "",
                "rows": rows,
            }
            self._save(job)
            return copy.deepcopy(job)

    def get(self, job_id, host):
        with self.lock:
            job = self._read(self._path(job_id))
            if job.get("host") != host:
                raise ValueError("SMS bulk job belongs to a different CUCM environment.")
            if job.get("status") in {"running", "queued"} and (self.worker is None or not self.worker.is_alive()):
                for row in job["rows"]:
                    if row.get("status") == "running":
                        row.update(status="needs_review", pattern_status="Unknown", ldap_status="Unknown", detail="Worker stopped during this row. Verify CUCM and LDAP manually; this row will not be replayed.")
                job.update(status="credentials_required", error="Worker stopped. Review interrupted rows, then explicitly recheck and resume only available pending rows.")
                self._save(job)
            return copy.deepcopy(job)

    def history(self, host):
        with self.lock:
            jobs = [self._read(path) for path in self.root.glob("*.json")]
            return sorted((job for job in jobs if job.get("host") == host), key=lambda job: job.get("created_at", ""), reverse=True)

    def check(self, job_id, host, validator):
        with self.lock:
            job = self.get(job_id, host)
            if job.get("status") in TERMINAL_JOB_STATES or job.get("status") == "running":
                raise ValueError("This SMS bulk job cannot be checked in its current state.")
            job["status"] = "checking"
            job["error"] = ""
            self._save(job)
            source_rows = copy.deepcopy(job["rows"])
        try:
            results = validator(source_rows)
        except Exception as exc:
            with self.lock:
                job = self.get(job_id, host)
                job.update(status="check_failed", error=f"Read-only availability check failed: {exc}")
                self._save(job)
                return copy.deepcopy(job)
        with self.lock:
            job = self.get(job_id, host)
            for index, row in enumerate(job["rows"]):
                if row.get("status") in TERMINAL_ROW_STATES:
                    continue
                result = results.get(str(row["row_id"]))
                if result:
                    job["rows"][index].update(result)
            job["reviewed_at"] = _now()
            job["status"] = "awaiting_confirmation" if any(row.get("status") == "available" for row in job["rows"]) else "no_available_rows"
            job["error"] = ""
            self._save(job)
            return copy.deepcopy(job)

    def start(self, job_id, host, operator, confirmation, execute):
        if confirmation != "BUILD":
            raise ValueError("Type BUILD to confirm creation of the available SMS translation patterns.")
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError("An SMS bulk worker is already running.")
            job = self.get(job_id, host)
            if job.get("status") != "awaiting_confirmation":
                raise ValueError("Check number availability first; no rows are ready to build.")
            try:
                reviewed_at = datetime.datetime.fromisoformat(job.get("reviewed_at", ""))
                age = datetime.datetime.now(datetime.timezone.utc) - reviewed_at
            except Exception:
                raise ValueError("Availability review timestamp is invalid; check the rows again.")
            if age.total_seconds() < 0 or age > datetime.timedelta(minutes=15):
                raise ValueError("Availability review is older than 15 minutes; check the rows again before building.")
            if not any(row.get("status") == "available" for row in job["rows"]):
                raise ValueError("No available rows to build.")
            job.update(status="running", started_at=_now(), started_by=operator, error="")
            self._save(job)
            self.worker = threading.Thread(target=self._run, args=(job_id, host, execute), daemon=True)
            self.worker.start()
            return copy.deepcopy(job)

    def _run(self, job_id, host, execute):
        try:
            job = self.get(job_id, host)
            for index in range(len(job["rows"])):
                with self.lock:
                    job = self.get(job_id, host)
                    if job.get("status") != "running":
                        return
                    row = job["rows"][index]
                    if row.get("status") != "available":
                        continue
                    row.update(status="running", started_at=_now())
                    self._save(job)
                    current_row = copy.deepcopy(row)
                try:
                    outcome = execute(current_row)
                except Exception as exc:
                    outcome = {"status": "needs_review", "pattern_status": "Unknown", "ldap_status": "Unknown", "detail": f"Row execution raised an exception; verify manually and do not replay: {exc}"}
                with self.lock:
                    job = self.get(job_id, host)
                    job["rows"][index].update(outcome)
                    job["rows"][index]["finished_at"] = _now()
                    self._save(job)
            with self.lock:
                job = self.get(job_id, host)
                if job.get("status") == "running":
                    job["status"] = "completed"
                    self._save(job)
        except Exception as exc:
            with self.lock:
                try:
                    job = self._read(self._path(job_id))
                except Exception:
                    return
                for row in job["rows"]:
                    if row.get("status") == "running":
                        row.update(status="needs_review", pattern_status="Unknown", ldap_status="Unknown", detail="Worker stopped during this row. Verify manually; this row will not be replayed.")
                if job.get("status") not in TERMINAL_JOB_STATES:
                    job["status"] = "credentials_required"
                job["error"] = f"Bulk worker stopped: {exc}"
                self._save(job)

    def control(self, job_id, host, action):
        with self.lock:
            job = self.get(job_id, host)
            if job.get("status") in TERMINAL_JOB_STATES:
                raise ValueError("SMS bulk job is already finished.")
            if action not in {"pause", "cancel"}:
                raise ValueError("Unknown SMS bulk control action.")
            job["status"] = "paused" if action == "pause" else "cancelled"
            if action == "cancel":
                for row in job["rows"]:
                    if row.get("status") == "available":
                        row.update(status="cancelled", detail="Cancelled before build; no changes made.")
            self._save(job)
            return copy.deepcopy(job)

    def recover(self):
        with self.lock:
            for path in self.root.glob("*.json"):
                job = self._read(path)
                changed = False
                for row in job["rows"]:
                    if row.get("status") == "running":
                        row.update(status="needs_review", pattern_status="Unknown", ldap_status="Unknown", detail="Service restarted during this row. Verify CUCM and LDAP manually; no automatic retry.")
                        changed = True
                if job.get("status") in {"queued", "running", "checking"}:
                    job["status"] = "credentials_required" if job.get("started_at") else "check_failed"
                    job["error"] = "Service restarted. Review any interrupted row; only rows still marked available can be explicitly resumed after a fresh availability check."
                    changed = True
                if changed:
                    self._save(job)

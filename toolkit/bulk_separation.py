import copy
import csv
import datetime
import io
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import uuid


RETENTION_DAYS = None
TERMINAL = {"completed", "cancelled"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def parse_emails(text):
    entries = list(dict.fromkeys(value.lower() for value in re.split(r"[\s,;]+", text.strip()) if value))
    if not entries or len(entries) > 5000:
        raise ValueError("Paste between 1 and 5,000 email entries.")
    return entries


def csv_bytes(job):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Email", "User ID", "Status", "Jabber Deleted", "Full Process", "Details", "Step Output", "CUCM Host", "Job ID", "Name", "Selected for Separation", "Extensions / Partitions", "Devices / Registration", "Registration Checked At", "Extension Is Translation Pattern", "Translation Pattern Matches", "Translation Pattern Checked At", "SMS", "SMS Matches", "SMS Inventory Fetched At", "SMS Inventory Expires At", "SMS Coverage", "SMS Scope", "SMS Inventory Failures"])
    for row in job["rows"]:
        values = [row.get(key, "") for key in ("email", "userid", "status", "deleted", "process", "detail", "output")]
        values.extend([job["host"], job["id"]])
        values.extend([row.get("name", ""), row.get("selected", ""),
            "; ".join(line["extension"] + "/" + line["partition"] for line in row.get("extensions", [])),
            "; ".join(line["device_name"] + " | " + line["extension"] + "/" + line["partition"] + " | " + line.get("registration", "Unknown") + " | Last registered: " + line.get("last_registered", "Unknown") + " | " + line["relationship"] for line in row.get("devices", [])), row.get("registration_checked_at", "")])
        values.extend([row.get("translation_pattern", "Not checked"), "; ".join(line["extension"] + "/" + line["partition"] for line in row.get("translation_pattern_matches", [])), row.get("translation_pattern_checked_at", "")])
        values.extend([row.get("sms", "Not checked"), "; ".join(match["provider"] + " | " + match["phone_number"] + " | " + match["environment"] + " / " + match["account"] for match in row.get("sms_matches", [])), row.get("sms_inventory_fetched_at") or "", row.get("sms_inventory_expires_at") or "", row.get("sms_inventory_status") or "", row.get("sms_inventory_scope") or "", "; ".join(row.get("sms_inventory_failures") or [])])
        writer.writerow(["'" + str(value) if str(value).lstrip().startswith(("=", "+", "-", "@")) else value for value in values])
    return output.getvalue().encode("utf-8-sig")


def fresh_build_csv_bytes(job):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email", "User ID", "Previous Jabber Devices (Reference Only)", "Previous Extensions / Partitions (Reference Only)", "Job Outcome", "Jabber Deleted", "Full Process", "Selected for Separation", "Job ID", "CUCM Host", "Review Details Available", "Fresh Build Note", "Extension Is Translation Pattern", "Translation Pattern Matches", "Translation Pattern Checked At", "SMS", "SMS Matches", "SMS Inventory Fetched At", "SMS Inventory Expires At", "SMS Coverage", "SMS Scope", "SMS Inventory Failures"])
    for row in job["rows"]:
        devices = sorted({line["device_name"] for line in row.get("target_snapshot", []) if line["device_name"].upper().startswith(("CSF", "TCT", "BOT", "TAB"))})
        has_review = "target_snapshot" in row and "extensions" in row
        values = [row.get("name", ""), row["email"], row.get("userid", ""), "; ".join(devices),
            "; ".join(line["extension"] + "/" + line["partition"] for line in row.get("extensions", [])),
            row["status"], row.get("deleted", "Not recorded"), row.get("process", "Not recorded"), row.get("selected", "Not recorded"),
            job["id"], job["host"], "Yes" if has_review else "No - older job did not capture review details",
            "Fresh build using current approved templates and current identity/number-availability checks; not a configuration or voicemail restore. Confirm the outcome before rebuilding; kept/failed/unknown entries may still have resources."]
        values.extend([row.get("translation_pattern", "Not checked"), "; ".join(line["extension"] + "/" + line["partition"] for line in row.get("translation_pattern_matches", [])), row.get("translation_pattern_checked_at", "")])
        values.extend([row.get("sms", "Not checked"), "; ".join(match["provider"] + " | " + match["phone_number"] + " | " + match["environment"] + " / " + match["account"] for match in row.get("sms_matches", [])), row.get("sms_inventory_fetched_at") or "", row.get("sms_inventory_expires_at") or "", row.get("sms_inventory_status") or "", row.get("sms_inventory_scope") or "", "; ".join(row.get("sms_inventory_failures") or [])])
        writer.writerow(["'" + str(value) if str(value).lstrip().startswith(("=", "+", "-", "@")) else value for value in values])
    return output.getvalue().encode("utf-8-sig")


def _sql_values(values):
    return ",".join("'" + str(value).replace("'", "''") + "'" for value in values)


def _paged_rows(read_sql, body):
    seen = set()
    for offset in range(0, 100000, 1000):
        rows = read_sql(f"SELECT SKIP {offset} FIRST 1000 {body}")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("Invalid CUCM review inventory response.")
        fingerprint = json.dumps(rows, sort_keys=True)
        if rows and fingerprint in seen:
            raise ValueError("Repeated CUCM review inventory page.")
        seen.add(fingerprint)
        yield from rows
        if len(rows) < 1000:
            return
    raise ValueError("CUCM review inventory exceeded its safe page limit.")


def target_inventory(userids, read_sql):
    people = {}
    for start in range(0, len(userids), 100):
        batch = userids[start:start + 100]
        for relationship in ("associated", "owner"):
            device_join = (
                "LEFT JOIN enduserdevicemap m ON m.fkenduser=u.pkid LEFT JOIN device d ON d.pkid=m.fkdevice "
                if relationship == "associated" else "LEFT JOIN device d ON d.fkenduser=u.pkid "
            )
            body = (
                "DISTINCT u.userid, u.firstname AS first_name, u.lastname AS last_name, u.displayname AS display_name, "
                "d.name AS device_name, n.dnorpattern AS extension, r.name AS partition, "
                "pn.dnorpattern AS primary_extension, pr.name AS primary_partition FROM enduser u "
                + device_join
                + "LEFT JOIN devicenumplanmap dm ON dm.fkdevice=d.pkid LEFT JOIN numplan n ON n.pkid=dm.fknumplan "
                "LEFT JOIN routepartition r ON r.pkid=n.fkroutepartition "
                "LEFT JOIN endusernumplanmap pm ON pm.fkenduser=u.pkid AND pm.tkdnusage=1 "
                "LEFT JOIN numplan pn ON pn.pkid=pm.fknumplan LEFT JOIN routepartition pr ON pr.pkid=pn.fkroutepartition "
                f"WHERE u.userid IN ({_sql_values(batch)}) ORDER BY u.userid, d.name, n.dnorpattern, r.name, pn.dnorpattern, pr.name"
            )
            for record in _paged_rows(read_sql, body):
                userid = str(record.get("userid") or "").strip()
                if userid not in batch:
                    raise ValueError("Review inventory returned an unexpected user.")
                person = people.setdefault(userid, {"name": " ".join(part for part in (record.get("first_name"), record.get("last_name")) if part).strip() or record.get("display_name") or userid, "target_snapshot": [], "extensions": []})
                primary = {"extension": str(record.get("primary_extension") or ""), "partition": str(record.get("primary_partition") or "")}
                if primary["extension"] and primary not in person["extensions"]:
                    person["extensions"].append(primary)
                device_name = str(record.get("device_name") or "").strip()
                if device_name:
                    line = {"device_name": device_name, "extension": str(record.get("extension") or ""), "partition": str(record.get("partition") or ""), "relationship": relationship}
                    if line not in person["target_snapshot"]:
                        person["target_snapshot"].append(line)
                    extension = {"extension": line["extension"], "partition": line["partition"]}
                    if extension["extension"] and extension not in person["extensions"]:
                        person["extensions"].append(extension)
    for person in people.values():
        person["target_snapshot"].sort(key=lambda line: (line["device_name"], line["extension"], line["partition"], line["relationship"]))
        person["extensions"].sort(key=lambda line: (line["extension"], line["partition"]))
    return people


def build_review(emails, identities, read_sql, registrations, progress=None):
    snapshots = {}
    people = {}
    for start in range(0, len(emails), 100):
        batch = emails[start:start + 100]
        if progress:
            progress(f"Reading CUCM End User extensions/devices: {start + 1}-{start + len(batch)} of {len(emails)}")
        valid = {email: identities.get(email) for email in batch if identities.get(email) and len(identities[email]) == 1}
        try:
            people.update(target_inventory(list(dict.fromkeys(matches[0]["userid"] for matches in valid.values())), read_sql))
            for email, matches in valid.items():
                userid = matches[0]["userid"]
                if userid in people:
                    snapshots[email] = {"userid": userid, **people[userid], "eligible": True, "devices": []}
        except Exception:
            for email in valid:
                snapshots[email] = {"eligible": False, "detail": "CUCM user/device inventory failed; excluded from separation."}
        for email in batch:
            snapshots.setdefault(email, {"eligible": False, "detail": "LDAP email-to-username / CUCM End User lookup failed or did not return one verified identity; excluded from separation."})
    by_extension = {}
    numbers = sorted({line["extension"] for person in people.values() for line in person["extensions"]})
    for start in range(0, len(numbers), 100):
        batch = numbers[start:start + 100]
        if progress:
            progress(f"Finding devices sharing extension digits: {start + 1}-{start + len(batch)} of {len(numbers)}")
        try:
            body = (
                "DISTINCT d.name AS device_name, n.dnorpattern AS extension, r.name AS partition "
                "FROM numplan n INNER JOIN devicenumplanmap dm ON dm.fknumplan=n.pkid "
                "INNER JOIN device d ON d.pkid=dm.fkdevice LEFT JOIN routepartition r ON r.pkid=n.fkroutepartition "
                f"WHERE n.dnorpattern IN ({_sql_values(batch)}) ORDER BY n.dnorpattern, d.name, r.name"
            )
            for record in _paged_rows(read_sql, body):
                extension = str(record.get("extension") or "")
                if extension not in batch or not record.get("device_name"):
                    raise ValueError("Invalid shared-extension device inventory.")
                by_extension.setdefault(extension, []).append({"device_name": record["device_name"], "extension": extension, "partition": str(record.get("partition") or ""), "relationship": "shared extension"})
        except Exception:
            for email, snapshot in snapshots.items():
                if any(line["extension"] in batch for line in snapshot.get("extensions", [])):
                    snapshot.update(eligible=False, detail="Shared-extension device lookup failed; excluded from separation.")
    for snapshot in snapshots.values():
        devices = {}
        for line in snapshot.get("target_snapshot", []):
            key = (line["device_name"], line["extension"], line["partition"])
            devices.setdefault(key, dict(line))
        for extension in snapshot.get("extensions", []):
            for line in by_extension.get(extension["extension"], []):
                devices.setdefault((line["device_name"], line["extension"], line["partition"]), dict(line))
        snapshot["devices"] = sorted(devices.values(), key=lambda line: (line["extension"], line["partition"], line["device_name"]))
    translation_matches = {}
    failed_translation_checks = set()
    for start in range(0, len(numbers), 100):
        batch = numbers[start:start + 100]
        if progress:
            progress(f"Checking exact-extension Translation Patterns: {start + 1}-{start + len(batch)} of {len(numbers)}")
        try:
            body = (
                "DISTINCT n.dnorpattern AS extension, r.name AS partition FROM numplan n "
                "LEFT JOIN routepartition r ON r.pkid=n.fkroutepartition "
                f"WHERE n.tkpatternusage IN (3,15) AND n.dnorpattern IN ({_sql_values(batch)}) ORDER BY n.dnorpattern, r.name"
            )
            for record in _paged_rows(read_sql, body):
                extension = str(record.get("extension") or "")
                if extension not in batch:
                    raise ValueError("Invalid translation pattern inventory response.")
                translation_matches.setdefault(extension, []).append({"extension": extension, "partition": str(record.get("partition") or "")})
        except Exception:
            failed_translation_checks.update(batch)
    translation_checked_at = now()
    for snapshot in snapshots.values():
        extensions = sorted({line["extension"] for line in snapshot.get("extensions", [])})
        snapshot["translation_pattern_checks"] = [{"extension": extension, "status": "Lookup Failed" if extension in failed_translation_checks else "Yes" if translation_matches.get(extension) else "No"} for extension in extensions]
        snapshot["translation_pattern_matches"] = [line for extension in extensions if extension not in failed_translation_checks for line in translation_matches.get(extension, [])]
        answers = {check["status"] for check in snapshot["translation_pattern_checks"]}
        snapshot["translation_pattern"] = "Yes" if "Yes" in answers else "Lookup Failed" if "Lookup Failed" in answers else "No" if answers else "Not checked"
        snapshot["translation_pattern_checked_at"] = translation_checked_at
    seen_users = {}
    for email, snapshot in snapshots.items():
        userid = str(snapshot.get("userid") or "").lower()
        if userid and snapshot.get("eligible"):
            if userid in seen_users:
                snapshot.update(eligible=False, detail=f"Duplicate verified employee; already represented by {seen_users[userid]}. No duplicate separation will run.")
            else:
                seen_users[userid] = email
    names = sorted({line["device_name"] for snapshot in snapshots.values() for line in snapshot["devices"]})
    if progress:
        for snapshot in snapshots.values():
            for line in snapshot["devices"]:
                line["registration"] = "Checking RIS"
        progress(f"Checking current RIS registration for {len(names)} devices; resolved identities/devices are shown below", snapshots)
    try:
        states = registrations(names) if names else {}
    except Exception:
        states = {}
    checked_at = now()
    for snapshot in snapshots.values():
        snapshot["registration_checked_at"] = checked_at
        for line in snapshot["devices"]:
            registration = states.get(line["device_name"]) or {}
            line["registration"] = str(registration.get("status") or "Unknown")
            line["last_registered"] = str(registration.get("last_registered") or "Unknown")
            line["registration_history_status"] = str(registration.get("history_status") or "Unknown")
            line["registration_source"] = str(registration.get("source") or "unknown")
    return snapshots


class BulkSeparationQueue:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.RLock()
        self.worker = None

    def _path(self, job_id):
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise ValueError("Invalid job ID.")
        return self.root / (job_id + ".json")

    def _read(self, path):
        with path.open(encoding="utf-8") as handle:
            job = json.load(handle)
        if job.get("version") != 1 or not isinstance(job.get("rows"), list) or job.get("id") != path.stem:
            raise ValueError("Invalid saved bulk separation state; restore runtime data before continuing.")
        return job

    def _save(self, job):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        job["updated_at"] = now()
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
                directory = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def history(self, host):
        with self.lock:
            jobs = [self._read(path) for path in self.root.glob("*.json")]
            retained = [job for job in jobs if job["host"] == host]
            return sorted(retained, key=lambda job: job["created_at"], reverse=True)

    def get(self, job_id, host):
        with self.lock:
            job = self._read(self._path(job_id))
            if job["host"] != host:
                raise ValueError("Job belongs to a different CUCM environment.")
            if job["status"] == "reviewing" and (self.worker is None or not self.worker.is_alive()):
                job.update(status="review_failed", error="Read-only review worker stopped. Refresh Review with current credentials; no separation was authorized.")
                self._save(job)
            return copy.deepcopy(job)

    def review_progress(self, job_id, host, stage, snapshots=None):
        with self.lock:
            job = self.get(job_id, host)
            if job["status"] != "reviewing":
                return
            job["review_progress"] = stage
            if snapshots:
                for row in job["rows"]:
                    if row["status"] == "pending" and row["email"] in snapshots:
                        row.update(copy.deepcopy(snapshots[row["email"]]))
            self._save(job)

    def recover(self):
        with self.lock:
            for path in self.root.glob("*.json"):
                job = self._read(path)
                changed = False
                for row in job["rows"]:
                    if row["status"] == "running":
                        row.update(status="needs_review", deleted="Unknown", process="Interrupted", detail="Service stopped during separation. Verify all systems manually; this entry will not be replayed.")
                        changed = True
                if job["status"] in {"queued", "running"}:
                    job["status"] = "credentials_required"
                    changed = True
                if job["status"] == "reviewing":
                    job.update(status="review_failed", error="Service restarted during read-only review. Retry review; no separation was started.")
                    changed = True
                if changed:
                    self._save(job)

    def submit(self, host, operator, text):
        emails = parse_emails(text)
        with self.lock:
            for path in self.root.glob("*.json"):
                existing = self._read(path)
                if existing["status"] not in TERMINAL:
                    raise ValueError("An unfinished bulk job exists. Resume or cancel it first.")
            job = {"version": 1, "id": uuid.uuid4().hex, "host": host, "operator": operator, "created_at": now(), "status": "queued", "rows": []}
            for email in emails:
                valid = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))
                job["rows"].append({"email": email, "userid": "", "status": "pending" if valid else "lookup_failed", "deleted": "Not attempted", "process": "Not started", "detail": "" if valid else "Invalid email address.", "output": ""})
            self._save(job)
            return copy.deepcopy(job)

    def review(self, job_id, host, preview):
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError("Wait for the current bulk worker to finish before preparing review.")
            job = self.get(job_id, host)
            if job["status"] in TERMINAL or job.get("approved_at"):
                raise ValueError("This job cannot be reviewed again. Resume approved pending work or submit a new list.")
            for row in job["rows"]:
                if row["status"] in {"pending", "lookup_failed"} and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", row["email"]):
                    row["status"] = "pending"
            job.update(status="reviewing", review_required=True, review_started_at=now(), review_progress="Starting LDAP email-to-username lookup", error="")
            self._save(job)
            self.worker = threading.Thread(target=self._review, args=(job_id, host, preview), daemon=True)
            self.worker.start()

    def _review(self, job_id, host, preview):
        try:
            job = self.get(job_id, host)
            pending = [row["email"] for row in job["rows"] if row["status"] == "pending"]
            snapshots = preview(pending)
            with self.lock:
                job = self.get(job_id, host)
                if job["status"] != "reviewing":
                    return
                for row in job["rows"]:
                    if row["status"] != "pending":
                        continue
                    snapshot = snapshots.get(row["email"])
                    selected = row.get("selected", True)
                    row.update({"userid": "", "name": "", "eligible": False, "devices": [], "extensions": [], "target_snapshot": []})
                    if snapshot:
                        row.update(snapshot)
                    if not snapshot or not snapshot.get("userid") or not snapshot.get("eligible"):
                        row.update(status="lookup_failed", selected=False, detail=(snapshot or {}).get("detail", "Review lookup failed; no changes made."))
                    else:
                        row.update(selected=selected)
                job.update(status="awaiting_review", reviewed_at=job["review_started_at"], review_progress="Review complete; verify employees and save exclusions before approval", selection_revision=uuid.uuid4().hex)
                self._save(job)
        except Exception:
            with self.lock:
                job = self.get(job_id, host)
                if job["status"] == "reviewing":
                    job.update(status="review_failed", error="Read-only review failed. No separation was started. Retry review with current credentials.")
                    self._save(job)

    def select(self, job_id, host, revision, selected_emails):
        with self.lock:
            job = self.get(job_id, host)
            if job["status"] != "awaiting_review" or job.get("selection_revision") != revision:
                raise ValueError("Review changed or is not ready. Reload the saved job before selecting.")
            if not isinstance(selected_emails, list) or len(selected_emails) != len(set(selected_emails)):
                raise ValueError("Invalid selection.")
            eligible = {row["email"] for row in job["rows"] if row["status"] == "pending" and row.get("eligible")}
            if not set(selected_emails).issubset(eligible):
                raise ValueError("Selection contains entries not eligible in this saved review.")
            for row in job["rows"]:
                row["selected"] = row["email"] in selected_emails
            job["selection_revision"] = uuid.uuid4().hex
            self._save(job)
            return job

    def approve(self, job_id, host, revision, operator):
        with self.lock:
            job = self.get(job_id, host)
            if job["status"] != "awaiting_review" or job.get("selection_revision") != revision:
                raise ValueError("Reload the saved review before approving separation.")
            age = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(job["reviewed_at"])
            if age.total_seconds() < 0 or age > datetime.timedelta(minutes=15):
                raise ValueError("Review is older than 15 minutes. Refresh review before authorizing separation.")
            if not any(row.get("selected") and row["status"] == "pending" for row in job["rows"]):
                raise ValueError("Select at least one employee for separation.")
            for row in job["rows"]:
                if row["status"] == "pending" and not row.get("selected"):
                    row.update(status="kept", deleted="Not attempted", process="Not started", detail="Kept by operator; excluded from full separation.")
            job.update(status="queued", approved_at=now(), approved_by=operator, approved_count=sum(row["status"] == "pending" and row.get("selected", False) for row in job["rows"]))
            self._save(job)
            return job

    def control(self, job_id, host, action):
        with self.lock:
            job = self.get(job_id, host)
            if job["status"] in TERMINAL:
                raise ValueError("Job is already finished.")
            if action not in {"pause", "cancel"}:
                raise ValueError("Unknown control.")
            if action == "pause" and job.get("review_required") and not job.get("approved_at"):
                raise ValueError("Review is read-only. Cancel the list or refresh review instead of pausing separation.")
            job["status"] = "paused" if action == "pause" else "cancelled"
            if action == "cancel":
                for row in job["rows"]:
                    if row["status"] == "pending":
                        row.update(status="cancelled", detail="Cancelled before separation; no changes made.")
            self._save(job)
            return job

    def start(self, job_id, host, resolve, execute):
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError("A bulk worker is still processing. Wait for the current person to finish.")
            job = self.get(job_id, host)
            if job["status"] in TERMINAL:
                raise ValueError("Job is already finished.")
            if job.get("review_required") and not job.get("approved_at"):
                raise ValueError("Review and approve selected employees before separation.")
            for row in job["rows"]:
                if row["status"] == "running":
                    row.update(status="needs_review", deleted="Unknown", process="Interrupted", detail="Previous worker stopped during separation. Verify manually; this entry will not be replayed.")
            job["status"] = "running"
            job["error"] = ""
            self._save(job)
            self.worker = threading.Thread(target=self._run, args=(job_id, host, resolve, execute), daemon=True)
            self.worker.start()

    def _run(self, job_id, host, resolve, execute):
        try:
            job = self.get(job_id, host)
            identities = resolve([row["email"] for row in job["rows"] if row["status"] == "pending"])
            for index in range(len(job["rows"])):
                with self.lock:
                    job = self.get(job_id, host)
                    if job["status"] != "running":
                        return
                    row = job["rows"][index]
                    if row["status"] != "pending":
                        continue
                    matches = identities.get(row["email"], [])
                    if matches is None:
                        row.update(status="lookup_failed", detail="CUCM email lookup failed for this batch; no changes made. Later entries continue.")
                        self._save(job)
                        continue
                    if len(matches) != 1 or not matches[0].get("userid"):
                        row.update(status="lookup_failed", detail="No unique exact CUCM email match; no changes made.")
                        self._save(job)
                        continue
                    if job.get("review_required") and (not row.get("selected") or row.get("userid") != matches[0]["userid"]):
                        row.update(status="needs_review", deleted="Not attempted", detail="Reviewed identity changed or entry is no longer selected; no changes made.")
                        self._save(job)
                        continue
                    row.update(userid=matches[0]["userid"], status="running")
                    self._save(job)
                    email, userid = row["email"], row["userid"]
                try:
                    result = execute(email, userid)
                except Exception:
                    result = {"status": "failed", "deleted": "Unknown", "process": "Failed", "detail": "Separation raised an exception. Verify systems manually; no automatic retry."}
                with self.lock:
                    job = self.get(job_id, host)
                    job["rows"][index].update(result)
                    self._save(job)
            with self.lock:
                job = self.get(job_id, host)
                if job["status"] == "running":
                    job["status"] = "completed"
                    self._save(job)
        except Exception:
            with self.lock:
                job = self.get(job_id, host)
                for row in job["rows"]:
                    if row["status"] == "running":
                        row.update(status="needs_review", deleted="Unknown", process="Interrupted", detail="Worker interrupted. Verify manually; no automatic retry.")
                if job["status"] not in TERMINAL:
                    job["status"] = "credentials_required"
                job["error"] = "Worker or email-inventory read failed. Check connectivity, credentials and runtime storage, then explicitly resume pending entries."
                self._save(job)
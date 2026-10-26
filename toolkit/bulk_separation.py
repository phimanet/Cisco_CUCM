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
import uuid


RETENTION_DAYS = 180
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
    writer.writerow(["Email", "User ID", "Status", "Jabber Deleted", "Full Process", "Details", "Step Output", "CUCM Host", "Job ID"])
    for row in job["rows"]:
        values = [row.get(key, "") for key in ("email", "userid", "status", "deleted", "process", "detail", "output")]
        values.extend([job["host"], job["id"]])
        writer.writerow(["'" + str(value) if str(value).lstrip().startswith(("=", "+", "-", "@")) else value for value in values])
    return output.getvalue().encode("utf-8-sig")


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
            os.replace(temporary, self._path(job["id"]))
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
            cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=RETENTION_DAYS)
            retained = []
            for job in jobs:
                if job["status"] in TERMINAL and datetime.datetime.fromisoformat(job["updated_at"]) < cutoff:
                    self._path(job["id"]).unlink()
                elif job["host"] == host:
                    retained.append(job)
            return sorted(retained, key=lambda job: job["created_at"], reverse=True)

    def get(self, job_id, host):
        with self.lock:
            job = self._read(self._path(job_id))
            if job["host"] != host:
                raise ValueError("Job belongs to a different CUCM environment.")
            return copy.deepcopy(job)

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

    def control(self, job_id, host, action):
        with self.lock:
            job = self.get(job_id, host)
            if job["status"] in TERMINAL:
                raise ValueError("Job is already finished.")
            if action not in {"pause", "cancel"}:
                raise ValueError("Unknown control.")
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
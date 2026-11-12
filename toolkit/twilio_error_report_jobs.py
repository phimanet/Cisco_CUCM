import copy
import datetime
import json
import os
import re
import tempfile
import threading
import time
from uuid import uuid4
from zoneinfo import ZoneInfo


UTC = datetime.timezone.utc
TIME_ZONE_NAME = "America/Los_Angeles"
LOOKBACK_HOURS = (4, 12, 24, 48, 168)
FREQUENCIES = {"daily", "weekly"}
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
RUN_RETENTION_DAYS = 90
MAX_RUNS_PER_JOB = 100
MAX_JOBS = 100
ACTIVE_RUN_STATUSES = {"running"}
_ACCOUNT_SID_RE = re.compile(r"AC[0-9a-fA-F]{32}")
_EMAIL_RE = re.compile(r"[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+")
_TIME_RE = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")


class TwilioErrorReportJobError(ValueError):
    pass


def _now_utc():
    return datetime.datetime.now(UTC)


def _iso_utc(value=None):
    return (value or _now_utc()).astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_datetime(value):
    if not isinstance(value, str):
        raise TwilioErrorReportJobError("Saved schedule time is invalid.")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TwilioErrorReportJobError("Saved schedule time is invalid.") from exc
    if parsed.tzinfo is None:
        raise TwilioErrorReportJobError("Saved schedule time must include a timezone.")
    return parsed.astimezone(UTC)


def _validate_job_fields(account_sid, account_name, lookback_hours, frequency, weekday, run_time, recipient):
    sid = str(account_sid or "").strip()
    name = str(account_name or "").strip()[:200]
    to = str(recipient or "").strip()
    if not _ACCOUNT_SID_RE.fullmatch(sid):
        raise TwilioErrorReportJobError("Select a valid Twilio account.")
    if not name:
        name = sid
    try:
        lookback = int(lookback_hours)
    except (TypeError, ValueError) as exc:
        raise TwilioErrorReportJobError("Select a supported trailing-hour window.") from exc
    if lookback not in LOOKBACK_HOURS:
        raise TwilioErrorReportJobError("Select a supported trailing-hour window.")
    cadence = str(frequency or "").strip().lower()
    if cadence not in FREQUENCIES:
        raise TwilioErrorReportJobError("Frequency must be Daily or Weekly.")
    day = str(weekday or "monday").strip().lower()
    if cadence == "weekly" and day not in WEEKDAYS:
        raise TwilioErrorReportJobError("Select a valid weekday for a weekly job.")
    if cadence == "daily":
        day = "monday"
    schedule_time = str(run_time or "").strip()
    if not _TIME_RE.fullmatch(schedule_time):
        raise TwilioErrorReportJobError("Choose a valid run time.")
    if not _EMAIL_RE.fullmatch(to):
        raise TwilioErrorReportJobError("Enter one valid email recipient.")
    return sid, name, lookback, cadence, day, schedule_time, to


def next_run_at(job, after=None):
    now = (after or _now_utc()).astimezone(UTC)
    zone = ZoneInfo(TIME_ZONE_NAME)
    local_now = now.astimezone(zone)
    hour, minute = (int(value) for value in job["run_time"].split(":"))
    if job["frequency"] == "daily":
        run_date = local_now.date()
        candidate_naive = datetime.datetime.combine(run_date, datetime.time(hour, minute))
        if candidate_naive <= local_now.replace(tzinfo=None):
            run_date += datetime.timedelta(days=1)
            candidate_naive = datetime.datetime.combine(run_date, datetime.time(hour, minute))
    elif job["frequency"] == "weekly":
        target_weekday = WEEKDAYS.index(job["weekday"])
        days_ahead = (target_weekday - local_now.weekday()) % 7
        run_date = local_now.date() + datetime.timedelta(days=days_ahead)
        candidate_naive = datetime.datetime.combine(run_date, datetime.time(hour, minute))
        if candidate_naive <= local_now.replace(tzinfo=None):
            run_date += datetime.timedelta(days=7)
            candidate_naive = datetime.datetime.combine(run_date, datetime.time(hour, minute))
    else:
        raise TwilioErrorReportJobError("Saved schedule frequency is invalid.")

    for _ in range(3):
        candidate = candidate_naive.replace(tzinfo=zone)
        round_trip = candidate.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
        if round_trip == candidate_naive:
            return _iso_utc(candidate)
        candidate_naive += datetime.timedelta(days=1 if job["frequency"] == "daily" else 7)
    raise TwilioErrorReportJobError("Could not calculate the next Pacific run time.")


class TwilioErrorReportJobStore:
    def __init__(self, directory):
        self.directory = os.path.abspath(directory)
        self.path = os.path.join(self.directory, "state.json")
        self.lock = threading.RLock()

    def _empty_state(self):
        return {"schema_version": 1, "jobs": [], "runs": []}

    def _load_unlocked(self):
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
        except FileNotFoundError:
            return self._empty_state()
        if not isinstance(state, dict) or state.get("schema_version") != 1 or not isinstance(state.get("jobs"), list) or not isinstance(state.get("runs"), list):
            raise TwilioErrorReportJobError("Saved Twilio email-job state is invalid and was not overwritten.")
        job_ids = set()
        for job in state["jobs"]:
            if not isinstance(job, dict) or not re.fullmatch(r"[0-9a-f]{32}", str(job.get("job_id", ""))):
                raise TwilioErrorReportJobError("Saved Twilio email-job definition is invalid and was not overwritten.")
            _validate_job_fields(
                job.get("account_sid"), job.get("account_name"), job.get("lookback_hours"),
                job.get("frequency"), job.get("weekday"), job.get("run_time"), job.get("recipient"),
            )
            if type(job.get("enabled")) is not bool:
                raise TwilioErrorReportJobError("Saved Twilio email-job status is invalid and was not overwritten.")
            job_ids.add(job["job_id"])
        for run in state["runs"]:
            if not isinstance(run, dict) or not re.fullmatch(r"[0-9a-f]{32}", str(run.get("run_id", ""))) or run.get("job_id") not in job_ids:
                raise TwilioErrorReportJobError("Saved Twilio email-job history is invalid and was not overwritten.")
            if run.get("status") not in {"running", "complete", "partial", "failed"} or not isinstance(run.get("rows"), list):
                raise TwilioErrorReportJobError("Saved Twilio email-job history is invalid and was not overwritten.")
        return state

    def _prune_unlocked(self, state, now=None):
        cutoff = (now or _now_utc()) - datetime.timedelta(days=RUN_RETENTION_DAYS)
        by_job = {}
        for run in state["runs"]:
            by_job.setdefault(run["job_id"], []).append(run)
        retained = []
        for runs in by_job.values():
            active = [run for run in runs if run.get("status") == "running" or run.get("email_status") in {"pending", "sending"}]
            completed = []
            for run in runs:
                if run in active:
                    continue
                try:
                    if _parse_datetime(run.get("created_at")) >= cutoff:
                        completed.append(run)
                except TwilioErrorReportJobError:
                    raise TwilioErrorReportJobError("Saved Twilio email-job history timestamp is invalid and was not overwritten.")
            completed.sort(key=lambda run: run["created_at"], reverse=True)
            retained.extend(active)
            retained.extend(completed[:MAX_RUNS_PER_JOB])
        state["runs"] = retained

    def _save_unlocked(self, state):
        os.makedirs(self.directory, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(self.directory, 0o700)
        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.directory, suffix=".tmp", delete=False) as handle:
                temp_path = handle.name
                json.dump(state, handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            for attempt in range(3):
                try:
                    os.replace(temp_path, self.path)
                    temp_path = ""
                    break
                except PermissionError:
                    if os.name != "nt" or attempt == 2:
                        raise
                    time.sleep(0.05 * (attempt + 1))
            try:
                directory_fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _mutate(self, callback):
        with self.lock:
            state = self._load_unlocked()
            result = callback(state)
            self._prune_unlocked(state)
            self._save_unlocked(state)
            return copy.deepcopy(result)

    def snapshot(self):
        with self.lock:
            state = self._load_unlocked()
            return copy.deepcopy(state)

    def prune_history(self, now=None):
        with self.lock:
            state = self._load_unlocked()
            before = len(state["runs"])
            self._prune_unlocked(state, now)
            removed = before - len(state["runs"])
            if removed:
                self._save_unlocked(state)
            return removed

    def create_job(self, account_sid, account_name, lookback_hours, frequency, weekday, run_time, recipient, operator):
        fields = _validate_job_fields(account_sid, account_name, lookback_hours, frequency, weekday, run_time, recipient)
        sid, name, lookback, cadence, day, schedule_time, to = fields
        now = _now_utc()
        job = {
            "job_id": uuid4().hex, "account_sid": sid, "account_name": name,
            "lookback_hours": lookback, "frequency": cadence, "weekday": day,
            "run_time": schedule_time, "time_zone": TIME_ZONE_NAME, "recipient": to,
            "enabled": True, "created_by": str(operator or "")[:128],
            "created_at": _iso_utc(now), "updated_at": _iso_utc(now), "next_run_at": "",
        }
        job["next_run_at"] = next_run_at(job, now)

        def add(state):
            if len(state["jobs"]) >= MAX_JOBS:
                raise TwilioErrorReportJobError(f"A maximum of {MAX_JOBS} scheduled jobs may be saved.")
            state["jobs"].append(job)
            return job
        return self._mutate(add)

    def set_enabled(self, job_id, enabled):
        if type(enabled) is not bool:
            raise TwilioErrorReportJobError("Invalid scheduled job action.")

        def change(state):
            job = next((item for item in state["jobs"] if item["job_id"] == job_id), None)
            if not job:
                raise TwilioErrorReportJobError("Scheduled job not found.")
            job["enabled"] = enabled
            job["updated_at"] = _iso_utc()
            if enabled:
                job["next_run_at"] = next_run_at(job)
            return job
        return self._mutate(change)

    def delete_job(self, job_id):
        def remove(state):
            if any(run["job_id"] == job_id and (run["status"] == "running" or run.get("email_status") in {"pending", "sending"}) for run in state["runs"]):
                raise TwilioErrorReportJobError("This job has a run in progress; pause it and try again after the run finishes.")
            before = len(state["jobs"])
            state["jobs"] = [job for job in state["jobs"] if job["job_id"] != job_id]
            if len(state["jobs"]) == before:
                raise TwilioErrorReportJobError("Scheduled job not found.")
            state["runs"] = [run for run in state["runs"] if run["job_id"] != job_id]
            return {"deleted": True, "job_id": job_id}
        return self._mutate(remove)

    def create_run(self, job_id, operator, triggered_by="manual"):
        now = _now_utc()
        run_id = uuid4().hex

        def add(state):
            job = next((item for item in state["jobs"] if item["job_id"] == job_id), None)
            if not job:
                raise TwilioErrorReportJobError("Scheduled job not found.")
            if any(run["job_id"] == job_id and (run["status"] == "running" or run.get("email_status") in {"pending", "sending"}) for run in state["runs"]):
                raise TwilioErrorReportJobError("This job already has a run in progress.")
            run = {
                "run_id": run_id, "job_id": job_id, "triggered_by": str(triggered_by or "manual"),
                "operator": str(operator or "")[:128], "status": "running", "email_status": "pending",
                "created_at": _iso_utc(now), "updated_at": _iso_utc(now),
                "account_sid": job["account_sid"], "account_name": job["account_name"],
                "start_time": _iso_utc(now - datetime.timedelta(hours=job["lookback_hours"])),
                "end_time": _iso_utc(now), "pages_read": 0, "next_uri": "", "rows": [],
                "row_count": 0, "complete": False, "error": "", "email_error": "",
            }
            state["runs"].append(run)
            return run
        return self._mutate(add)

    def claim_due_jobs(self, now=None):
        current = (now or _now_utc()).astimezone(UTC)
        now_text = _iso_utc(current)
        with self.lock:
            state = self._load_unlocked()
            claimed = []
            active_job_ids = {
                run["job_id"] for run in state["runs"]
                if run["status"] == "running" or run.get("email_status") in {"pending", "sending"}
            }
            for job in state["jobs"]:
                if not job["enabled"] or job["job_id"] in active_job_ids:
                    continue
                if _parse_datetime(job["next_run_at"]) > current:
                    continue
                run = self._new_scheduled_run(job, now_text, current)
                state["runs"].append(run)
                job["next_run_at"] = next_run_at(job, current)
                job["updated_at"] = now_text
                claimed.append(run)
            if not claimed:
                return []
            self._prune_unlocked(state, current)
            self._save_unlocked(state)
            return copy.deepcopy(claimed)

    @staticmethod
    def _new_scheduled_run(job, now_text, now):
        return {
            "run_id": uuid4().hex, "job_id": job["job_id"], "triggered_by": "scheduler",
            "operator": "scheduler", "status": "running", "email_status": "pending",
            "created_at": now_text, "updated_at": now_text,
                "account_sid": job["account_sid"], "account_name": job["account_name"],
            "start_time": _iso_utc(now - datetime.timedelta(hours=job["lookback_hours"])),
            "end_time": now_text, "pages_read": 0, "next_uri": "", "rows": [],
            "row_count": 0, "complete": False, "error": "", "email_error": "",
        }

    def update_run(self, run_id, **changes):
        allowed = {"status", "email_status", "updated_at", "pages_read", "next_uri", "rows", "row_count", "complete", "error", "email_error"}
        if set(changes) - allowed:
            raise TwilioErrorReportJobError("Invalid run-state update.")

        def update(state):
            run = next((item for item in state["runs"] if item["run_id"] == run_id), None)
            if not run:
                raise TwilioErrorReportJobError("Scheduled run not found.")
            run.update(changes)
            run["updated_at"] = _iso_utc()
            return run
        return self._mutate(update)

    def active_runs(self):
        with self.lock:
            state = self._load_unlocked()
            active = [run for run in state["runs"] if run["status"] == "running"]
            active.sort(key=lambda run: run["updated_at"])
            return copy.deepcopy(active)

    def pending_email_runs(self):
        with self.lock:
            state = self._load_unlocked()
            return copy.deepcopy([
                run for run in state["runs"]
                if run["status"] in {"complete", "partial", "failed"} and run.get("email_status") == "pending"
            ])

    def retry_email(self, run_id):
        def retry(state):
            run = next((item for item in state["runs"] if item["run_id"] == run_id), None)
            if not run:
                raise TwilioErrorReportJobError("Scheduled run not found.")
            if run["status"] not in {"complete", "partial", "failed"} or run.get("email_status") not in {"failed", "unknown"}:
                raise TwilioErrorReportJobError("Only a failed or uncertain delivery can be retried.")
            run["email_status"] = "pending"
            run["email_error"] = ""
            run["updated_at"] = _iso_utc()
            return run
        return self._mutate(retry)

    def get_run_context(self, run_id):
        with self.lock:
            state = self._load_unlocked()
            run = next((item for item in state["runs"] if item["run_id"] == run_id), None)
            if not run:
                raise TwilioErrorReportJobError("Scheduled run not found.")
            job = next((item for item in state["jobs"] if item["job_id"] == run["job_id"]), None)
            if not job:
                raise TwilioErrorReportJobError("Scheduled job was removed.")
            return copy.deepcopy(job), copy.deepcopy(run)

    def recover_uncertain_emails(self):
        def recover(state):
            recovered = 0
            for run in state["runs"]:
                if run.get("email_status") == "sending":
                    run["email_status"] = "unknown"
                    run["email_error"] = "Service restarted during email send; delivery is uncertain and was not automatically retried."
                    run["updated_at"] = _iso_utc()
                    recovered += 1
            return recovered
        return self._mutate(recover)


def record_page(store, run_id, report):
    _, run = store.get_run_context(run_id)
    if str(report.get("account_sid", "") or "") != run["account_sid"]:
        raise TwilioErrorReportJobError("Twilio returned a report for a different account.")
    if not isinstance(report.get("rows"), list):
        raise TwilioErrorReportJobError("Twilio returned an invalid report page.")
    merged = {row["message_sid"]: row for row in run["rows"] if isinstance(row, dict) and row.get("message_sid")}
    for row in report["rows"]:
        if not isinstance(row, dict) or str(row.get("account_sid", "") or "") != run["account_sid"]:
            raise TwilioErrorReportJobError("Twilio returned a row for a different account.")
        sid = str(row.get("message_sid", "") or "").strip()
        if sid:
            merged[sid] = row

    next_uri = str(report.get("next_uri", "") or "")
    error = str(report.get("error", "") or "")
    complete = bool(report.get("complete"))
    pages_read = int(report.get("pages_read", run["pages_read"]) or run["pages_read"])
    terminal = bool(error) or complete or not next_uri
    status = run["status"]
    email_status = run.get("email_status", "pending")
    if terminal:
        status = "complete" if complete else ("partial" if pages_read or merged else "failed")
        email_status = "pending"

    return store.update_run(
        run_id,
        status=status,
        email_status=email_status,
        pages_read=pages_read,
        next_uri=next_uri,
        rows=sorted(merged.values(), key=lambda row: (row.get("date_sent", ""), row.get("to", "")), reverse=True),
        row_count=len(merged),
        complete=complete,
        error=error,
    )


def advance_run(store, run_id, account_resolver, page_reader):
    job, run = store.get_run_context(run_id)
    if run["status"] != "running":
        return run
    try:
        account = account_resolver(job["account_sid"])
        if not isinstance(account, dict) or account.get("sid") != job["account_sid"]:
            raise TwilioErrorReportJobError("The scheduled Twilio account is no longer available.")
        report = page_reader(
            account,
            run["start_time"],
            run["end_time"],
            next_uri=run["next_uri"],
            pages_read=run["pages_read"],
            page_limit=1,
        )
        return record_page(store, run_id, report)
    except Exception:
        status = "partial" if run["pages_read"] or run["rows"] else "failed"
        return store.update_run(
            run_id,
            status=status,
            email_status="pending",
            complete=False,
            error="Scheduled Twilio search could not complete; coverage may be partial.",
        )


def deliver_pending_emails(store, sender):
    outcomes = []
    for candidate in store.pending_email_runs():
        job, run = store.get_run_context(candidate["run_id"])
        store.update_run(run["run_id"], email_status="sending")
        try:
            sender(job, run)
        except Exception:
            store.update_run(
                run["run_id"],
                email_status="failed",
                email_error="Email delivery failed. Retry manually after checking SMTP and recipient settings.",
            )
            outcomes.append({"run_id": run["run_id"], "sent": False})
        else:
            store.update_run(
                run["run_id"], email_status="sent", email_error="",
                row_count=len(run["rows"]), rows=[],
            )
            outcomes.append({"run_id": run["run_id"], "sent": True})
    return outcomes
import datetime
import ast
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from unittest.mock import Mock

from toolkit import twilio_error_report_jobs as jobs


ACCOUNT_SID = "AC" + "a" * 32


class TwilioErrorReportJobStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        timezone = datetime.timezone(datetime.timedelta(hours=-8))
        timezone_patch = patch.object(jobs, "ZoneInfo", return_value=timezone)
        timezone_patch.start()
        self.addCleanup(timezone_patch.stop)
        self.store = jobs.TwilioErrorReportJobStore(self.directory.name)

    def create_job(self, **overrides):
        values = {
            "account_sid": ACCOUNT_SID,
            "account_name": "Test Account",
            "lookback_hours": 24,
            "frequency": "daily",
            "weekday": "monday",
            "run_time": "08:30",
            "recipient": "laura.alvarez@amnhealthcare.com",
            "operator": "admin",
        }
        values.update(overrides)
        return self.store.create_job(**values)

    def test_daily_run_time_uses_pacific_timezone_and_skips_elapsed_time(self):
        job = {"frequency": "daily", "weekday": "monday", "run_time": "08:30"}

        before = jobs.next_run_at(job, datetime.datetime(2026, 1, 5, 15, 0, tzinfo=datetime.timezone.utc))
        after = jobs.next_run_at(job, datetime.datetime(2026, 1, 5, 18, 0, tzinfo=datetime.timezone.utc))

        self.assertEqual(before, "2026-01-05T16:30:00Z")
        self.assertEqual(after, "2026-01-06T16:30:00Z")

    def test_weekly_run_time_uses_selected_weekday(self):
        job = {"frequency": "weekly", "weekday": "monday", "run_time": "08:30"}

        result = jobs.next_run_at(job, datetime.datetime(2026, 1, 6, 18, 0, tzinfo=datetime.timezone.utc))

        self.assertEqual(result, "2026-01-12T16:30:00Z")

    def test_create_and_manual_run_persist_without_credentials(self):
        job = self.create_job()
        run = self.store.create_run(job["job_id"], "admin", "manual")
        restored = jobs.TwilioErrorReportJobStore(self.directory.name).snapshot()

        self.assertEqual(restored["jobs"][0]["job_id"], job["job_id"])
        self.assertEqual(restored["runs"][0]["run_id"], run["run_id"])
        self.assertEqual(restored["runs"][0]["status"], "running")
        with open(self.store.path, "r", encoding="utf-8") as handle:
            saved_text = handle.read()
        self.assertNotIn("auth_token", saved_text)
        self.assertNotIn("password", saved_text)

    def test_prevents_duplicate_run_and_persists_page_checkpoint(self):
        job = self.create_job()
        run = self.store.create_run(job["job_id"], "admin")
        with self.assertRaises(jobs.TwilioErrorReportJobError):
            self.store.create_run(job["job_id"], "admin")

        self.store.update_run(run["run_id"], pages_read=1, next_uri="/next", rows=[{"message_sid": "SM1"}])
        saved_job, saved_run = jobs.TwilioErrorReportJobStore(self.directory.name).get_run_context(run["run_id"])

        self.assertEqual(saved_job["job_id"], job["job_id"])
        self.assertEqual(saved_run["pages_read"], 1)
        self.assertEqual(saved_run["next_uri"], "/next")
        self.assertEqual(saved_run["rows"], [{"message_sid": "SM1"}])

    def test_restart_marks_interrupted_email_uncertain_without_resend(self):
        job = self.create_job()
        run = self.store.create_run(job["job_id"], "admin")
        self.store.update_run(run["run_id"], status="complete", email_status="sending")

        recovered = self.store.recover_uncertain_emails()
        saved_run = self.store.snapshot()["runs"][0]

        self.assertEqual(recovered, 1)
        self.assertEqual(saved_run["email_status"], "unknown")
        self.assertIn("not automatically retried", saved_run["email_error"])
        retried = self.store.retry_email(run["run_id"])
        self.assertEqual(retried["email_status"], "pending")
        self.assertEqual(len(self.store.pending_email_runs()), 1)

    def test_record_page_checkpoints_and_merges_until_complete(self):
        job = self.create_job()
        run = self.store.create_run(job["job_id"], "admin")
        first = {
            "account_sid": ACCOUNT_SID, "pages_read": 1,
            "next_uri": f"/2010-04-01/Accounts/{ACCOUNT_SID}/Messages.json?PageToken=next",
            "complete": False, "error": "", "rows": [{
                "account_sid": ACCOUNT_SID, "message_sid": "SM1", "date_sent": "2026-01-01T10:00:00Z", "to": "+12125550101",
            }],
        }
        second = {
            "account_sid": ACCOUNT_SID, "pages_read": 2, "next_uri": "",
            "complete": True, "error": "", "rows": [{
                "account_sid": ACCOUNT_SID, "message_sid": "SM2", "date_sent": "2026-01-01T11:00:00Z", "to": "+12125550102",
            }],
        }

        first_state = jobs.record_page(self.store, run["run_id"], first)
        final_state = jobs.record_page(self.store, run["run_id"], second)

        self.assertEqual(first_state["status"], "running")
        self.assertEqual(first_state["pages_read"], 1)
        self.assertEqual(final_state["status"], "complete")
        self.assertEqual(len(final_state["rows"]), 2)
        self.assertEqual({row["message_sid"] for row in final_state["rows"]}, {"SM1", "SM2"})

    def test_advance_run_resolves_account_and_resumes_cursor(self):
        job = self.create_job()
        run = self.store.create_run(job["job_id"], "admin")
        account = {"sid": ACCOUNT_SID, "auth_sid": ACCOUNT_SID, "auth_token": "secret"}
        resolver = Mock(return_value=account)
        first_page = {
            "account_sid": ACCOUNT_SID, "pages_read": 1,
            "next_uri": f"/2010-04-01/Accounts/{ACCOUNT_SID}/Messages.json?PageToken=next",
            "complete": False, "error": "", "rows": [],
        }
        final_page = {"account_sid": ACCOUNT_SID, "pages_read": 2, "next_uri": "", "complete": True, "error": "", "rows": []}
        reader = Mock(side_effect=[first_page, final_page])

        first = jobs.advance_run(self.store, run["run_id"], resolver, reader)
        final = jobs.advance_run(self.store, run["run_id"], resolver, reader)

        self.assertEqual(first["status"], "running")
        self.assertEqual(final["status"], "complete")
        self.assertEqual(reader.call_args_list[1].kwargs["next_uri"], first_page["next_uri"])
        self.assertEqual(reader.call_args_list[1].kwargs["page_limit"], 1)
        self.assertEqual(resolver.call_count, 2)

    def test_email_failure_is_explicit_and_retry_clears_rows_after_success(self):
        job = self.create_job()
        run = self.store.create_run(job["job_id"], "admin")
        self.store.update_run(
            run["run_id"], status="complete", complete=True,
            rows=[{"message_sid": "SM1"}], row_count=1,
        )
        failed_send = Mock(side_effect=RuntimeError("SMTP unavailable"))

        first_result = jobs.deliver_pending_emails(self.store, failed_send)
        failed_run = self.store.snapshot()["runs"][0]
        self.assertEqual(first_result, [{"run_id": run["run_id"], "sent": False}])
        self.assertEqual(failed_run["email_status"], "failed")
        self.assertEqual(failed_run["rows"], [{"message_sid": "SM1"}])

        self.store.retry_email(run["run_id"])
        successful_send = Mock()
        second_result = jobs.deliver_pending_emails(self.store, successful_send)
        saved_run = self.store.snapshot()["runs"][0]
        self.assertEqual(second_result, [{"run_id": run["run_id"], "sent": True}])
        self.assertEqual(saved_run["email_status"], "sent")
        self.assertEqual(saved_run["row_count"], 1)
        self.assertEqual(saved_run["rows"], [])

    def test_pause_resume_and_delete_reject_active_run(self):
        job = self.create_job()
        run = self.store.create_run(job["job_id"], "admin")
        paused = self.store.set_enabled(job["job_id"], False)
        self.assertFalse(paused["enabled"])
        with self.assertRaises(jobs.TwilioErrorReportJobError):
            self.store.delete_job(job["job_id"])

        self.store.update_run(run["run_id"], status="complete", email_status="sent")
        resumed = self.store.set_enabled(job["job_id"], True)
        self.assertTrue(resumed["enabled"])
        self.assertTrue(self.store.delete_job(job["job_id"])["deleted"])

    def test_due_job_is_claimed_once_and_next_run_advances(self):
        job = self.create_job(run_time="08:30")
        due_at = datetime.datetime(2026, 1, 5, 16, 30, tzinfo=datetime.timezone.utc)
        self.store._mutate(lambda state: state["jobs"][0].update(next_run_at="2026-01-05T16:30:00Z"))

        first = self.store.claim_due_jobs(due_at)
        second = self.store.claim_due_jobs(due_at)

        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["job_id"], job["job_id"])
        self.assertEqual(second, [])
        current_job = self.store.snapshot()["jobs"][0]
        self.assertEqual(current_job["next_run_at"], "2026-01-06T16:30:00Z")

    def test_history_retention_keeps_active_and_caps_recent_runs(self):
        job = self.create_job()
        now = datetime.datetime.now(datetime.timezone.utc)
        runs = []
        for index in range(jobs.MAX_RUNS_PER_JOB + 1):
            created = jobs._iso_utc(now - datetime.timedelta(days=1, seconds=index))
            runs.append({"run_id": f"{index + 1:032x}", "job_id": job["job_id"], "status": "complete", "rows": [], "created_at": created})
        old_run = {"run_id": "f" * 32, "job_id": job["job_id"], "status": "complete", "rows": [], "created_at": jobs._iso_utc(now - datetime.timedelta(days=91))}
        active_run = {"run_id": "e" * 32, "job_id": job["job_id"], "status": "running", "email_status": "pending", "rows": [], "created_at": jobs._iso_utc(now - datetime.timedelta(days=120))}
        self.store._mutate(lambda state: state.update(runs=runs + [old_run, active_run]))

        retained = self.store.snapshot()["runs"]

        self.assertEqual(len(retained), jobs.MAX_RUNS_PER_JOB + 1)
        self.assertIn(active_run["run_id"], {run["run_id"] for run in retained})
        self.assertNotIn(old_run["run_id"], {run["run_id"] for run in retained})

    def test_corrupt_state_is_refused_without_overwrite(self):
        with open(self.store.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"schema_version": 99, "jobs": [], "runs": []}))

        with self.assertRaises(jobs.TwilioErrorReportJobError):
            self.store.snapshot()
        with open(self.store.path, "r", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["schema_version"], 99)


class TwilioErrorReportJobRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        names = {
            "_twilio_error_report_jobs_public_state",
            "twilio_error_report_jobs_get_route",
            "twilio_error_report_jobs_create_route",
            "twilio_error_report_jobs_action_route",
        }
        cls.nodes = [
            ast.FunctionDef(name=node.name, args=node.args, body=node.body, decorator_list=[], returns=node.returns, type_comment=None)
            for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names
        ]

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        timezone = datetime.timezone(datetime.timedelta(hours=-8))
        timezone_patch = patch.object(jobs, "ZoneInfo", return_value=timezone)
        timezone_patch.start()
        self.addCleanup(timezone_patch.stop)
        self.store = jobs.TwilioErrorReportJobStore(self.directory.name)
        self.admin = Mock(return_value=True)
        self.audit = Mock()
        self.scope = {
            "Request": object,
            "Form": lambda value: value,
            "JSONResponse": lambda content, status_code=200, headers=None: SimpleNamespace(content=content, status_code=status_code, headers=headers),
            "re": re,
            "twilio_error_report_jobs": jobs,
            "TWILIO_ERROR_REPORT_JOBS_STORE": self.store,
            "_get_auth_session": Mock(return_value={"username": "admin"}),
            "_is_admin_user": self.admin,
            "_twilio_error_report_job_account": Mock(return_value={"sid": ACCOUNT_SID, "account_name": "Test Account"}),
            "_append_audit_event": self.audit,
            "logger": Mock(),
        }
        module = ast.fix_missing_locations(ast.Module(body=self.nodes, type_ignores=[]))
        exec(compile(module, "main.py", "exec"), self.scope)
        self.request = SimpleNamespace()

    def create(self, account_sid=ACCOUNT_SID):
        return self.scope["twilio_error_report_jobs_create_route"](
            self.request, account_sid, 24, "daily", "monday", "08:00", "laura.alvarez@amnhealthcare.com"
        )

    def test_create_multiple_account_jobs_and_admin_guard(self):
        first = self.create()
        self.scope["_twilio_error_report_job_account"].return_value = {"sid": "AC" + "b" * 32, "account_name": "Second"}
        second = self.create("AC" + "b" * 32)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(self.store.snapshot()["jobs"]), 2)
        self.admin.return_value = False
        denied = self.create("AC" + "c" * 32)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(len(self.store.snapshot()["jobs"]), 2)

    def test_authenticated_job_actions_and_run_retry(self):
        job = self.store.create_job(ACCOUNT_SID, "Test Account", 24, "daily", "monday", "08:00", "laura.alvarez@amnhealthcare.com", "admin")
        action_route = self.scope["twilio_error_report_jobs_action_route"]

        paused = action_route(self.request, job["job_id"], "pause", "")
        self.assertEqual(paused.status_code, 200, paused.content)
        self.assertFalse(self.store.snapshot()["jobs"][0]["enabled"])
        run = action_route(self.request, job["job_id"], "run-now", "").content["jobs"][0]["runs"][0]
        self.assertEqual(run["status"], "running")
        self.store.update_run(run["run_id"], status="complete", email_status="failed")
        retried = action_route(self.request, job["job_id"], "retry-email", run["run_id"])
        self.assertEqual(retried.status_code, 200)
        self.assertEqual(self.store.snapshot()["runs"][0]["email_status"], "pending")
        blocked_delete = action_route(self.request, job["job_id"], "delete", "")
        self.assertEqual(blocked_delete.status_code, 422)
        self.store.update_run(run["run_id"], status="complete", email_status="sent", rows=[])
        deleted = action_route(self.request, job["job_id"], "delete", "")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.store.snapshot()["jobs"], [])


if __name__ == "__main__":
    unittest.main()
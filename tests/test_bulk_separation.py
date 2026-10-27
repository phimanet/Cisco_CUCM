import tempfile
import ast
import csv
import datetime
import io
import json
from pathlib import Path
import re
import sqlite3
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from toolkit import bulk_separation
from toolkit.bulk_separation import BulkSeparationQueue, csv_bytes, parse_emails


class BulkSeparationTests(unittest.TestCase):
    def test_review_is_read_only_and_kept_employee_is_never_separated(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com b@example.com")
            execute = Mock(return_value={"status": "deleted"})
            queue.review(job["id"], "lab", lambda emails: {email: {"userid": email, "name": "Employee", "eligible": True, "devices": []} for email in emails})
            queue.worker.join(5)
            saved = queue.get(job["id"], "lab")
            self.assertEqual(saved["status"], "awaiting_review")
            execute.assert_not_called()
            with self.assertRaises(ValueError):
                queue.start(job["id"], "lab", Mock(), execute)
            selected = queue.select(job["id"], "lab", saved["selection_revision"], ["a@example.com"])
            restored = BulkSeparationQueue(root)
            self.assertFalse(restored.get(job["id"], "lab")["rows"][1]["selected"])
            restored.approve(job["id"], "lab", selected["selection_revision"], "admin")
            restored.start(job["id"], "lab", lambda emails: {email: [{"userid": email}] for email in emails}, execute)
            restored.worker.join(5)
            execute.assert_called_once_with("a@example.com", "a@example.com")
            self.assertEqual(restored.get(job["id"], "lab")["rows"][1]["status"], "kept")

    def test_review_refresh_preserves_deselection_and_requires_fresh_revision(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com b@example.com")
            preview = lambda emails: {email: {"userid": email, "eligible": True} for email in emails}
            queue.review(job["id"], "lab", preview)
            queue.worker.join(5)
            saved = queue.get(job["id"], "lab")
            selected = queue.select(job["id"], "lab", saved["selection_revision"], ["a@example.com"])
            with self.assertRaises(ValueError):
                queue.approve(job["id"], "lab", saved["selection_revision"], "admin")
            queue.review(job["id"], "lab", preview)
            queue.worker.join(5)
            refreshed = queue.get(job["id"], "lab")
            self.assertFalse(refreshed["rows"][1]["selected"])
            with self.assertRaises(ValueError):
                queue.select(job["id"], "lab", selected["selection_revision"], ["a@example.com", "b@example.com"])

    def test_expired_review_and_invalid_selection_cannot_start(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            queue.review(job["id"], "lab", lambda emails: {emails[0]: {"userid": "a", "eligible": True}})
            queue.worker.join(5)
            saved = queue.get(job["id"], "lab")
            with self.assertRaises(ValueError):
                queue.select(job["id"], "lab", saved["selection_revision"], ["other@example.com"])
            saved["reviewed_at"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=16)).isoformat()
            queue._save(saved)
            with self.assertRaisesRegex(ValueError, "older than 15 minutes"):
                queue.approve(job["id"], "lab", saved["selection_revision"], "admin")

    def test_review_restart_never_starts_separation(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            job.update(status="reviewing", review_required=True)
            queue._save(job)
            queue.recover()
            saved = queue.get(job["id"], "lab")
            self.assertEqual(saved["status"], "review_failed")
            with self.assertRaises(ValueError):
                queue.start(job["id"], "lab", Mock(), Mock())

    def test_entries_and_failure_continuation(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com; missing@example.com bad b@example.com A@example.com")
            calls = []

            def execute(email, userid):
                calls.append(userid)
                if userid == "a":
                    raise RuntimeError("secret provider response")
                return {"status": "deleted", "deleted": "Yes", "process": "Completed"}

            queue.start(job["id"], "lab", lambda emails: {"a@example.com": [{"userid": "a"}], "b@example.com": [{"userid": "b"}]}, execute)
            queue.worker.join(5)
            saved = BulkSeparationQueue(root).get(job["id"], "lab")
            self.assertEqual(calls, ["a", "b"])
            self.assertEqual([row["status"] for row in saved["rows"]], ["failed", "lookup_failed", "lookup_failed", "deleted"])
            self.assertEqual(saved["status"], "completed")
            self.assertNotIn("secret", str(saved))

    def test_restart_never_replays_inflight_or_completed(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com b@example.com c@example.com")
            job["status"] = "running"
            job["rows"][0]["status"] = "deleted"
            job["rows"][1]["status"] = "running"
            queue._save(job)
            restored = BulkSeparationQueue(root)
            restored.recover()
            self.assertEqual(restored.get(job["id"], "lab")["rows"][1]["status"], "needs_review")
            calls = []
            restored.start(job["id"], "lab", lambda emails: {email: [{"userid": email}] for email in emails}, lambda email, userid: calls.append(email) or {"status": "deleted"})
            restored.worker.join(5)
            self.assertEqual(calls, ["c@example.com"])

    def test_corruption_and_environment_refused(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            with self.assertRaises(ValueError):
                queue.get(job["id"], "prod")
            queue._path(job["id"]).write_text("invalid", encoding="utf-8")
            with self.assertRaises(ValueError):
                queue.submit("lab", "admin", "b@example.com")

    def test_large_input_and_csv(self):
        self.assertEqual(len(parse_emails(" ".join(f"user{index}@example.com" for index in range(150)))), 150)
        with tempfile.TemporaryDirectory() as root:
            job = BulkSeparationQueue(root).submit("lab", "admin", "=a@example.com")
            self.assertIn("'=a@example.com", csv_bytes(job).decode("utf-8-sig"))

    def test_pause_cancel_and_recovery_keep_inflight_review(self):
        for action in ("pause", "cancel"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as root:
                queue = BulkSeparationQueue(root)
                job = queue.submit("lab", "admin", "a@example.com b@example.com")
                job["status"] = "running"
                job["rows"][0]["status"] = "running"
                queue._save(job)
                queue.control(job["id"], "lab", action)
                queue.recover()
                restored = queue.get(job["id"], "lab")
                self.assertEqual(restored["status"], "paused" if action == "pause" else "cancelled")
                self.assertEqual(restored["rows"][0]["status"], "needs_review")

    def test_worker_failure_can_resume_pending_with_new_worker(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            queue.start(job["id"], "lab", Mock(side_effect=RuntimeError("lookup failed")), Mock())
            queue.worker.join(5)
            self.assertEqual(queue.get(job["id"], "lab")["status"], "credentials_required")
            queue.start(job["id"], "lab", lambda emails: {emails[0]: [{"userid": "a"}]}, lambda *args: {"status": "deleted"})
            queue.worker.join(5)
            self.assertEqual(queue.get(job["id"], "lab")["status"], "completed")

    def test_pause_during_execution_saves_result_and_stops_next_person(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com b@example.com")
            entered, release = threading.Event(), threading.Event()
            calls = []

            def execute(email, userid):
                calls.append(email)
                entered.set()
                release.wait(5)
                return {"status": "deleted", "deleted": "Yes"}

            queue.start(job["id"], "lab", lambda emails: {email: [{"userid": email}] for email in emails}, execute)
            self.assertTrue(entered.wait(5))
            queue.control(job["id"], "lab", "pause")
            release.set()
            queue.worker.join(5)
            saved = queue.get(job["id"], "lab")
            self.assertEqual(saved["status"], "paused")
            self.assertEqual([row["status"] for row in saved["rows"]], ["deleted", "pending"])
            self.assertEqual(len(calls), 1)

    def test_atomic_write_failure_keeps_previous_state(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            with patch("toolkit.bulk_separation.os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    queue.control(job["id"], "lab", "cancel")
            self.assertEqual(queue.get(job["id"], "lab")["status"], "queued")

    def test_dead_worker_resume_marks_inflight_review_without_replay(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com b@example.com")
            job["status"] = "running"
            job["rows"][0]["status"] = "running"
            queue._save(job)
            execute = Mock(return_value={"status": "deleted"})
            queue.start(job["id"], "lab", lambda emails: {email: [{"userid": email}] for email in emails}, execute)
            queue.worker.join(5)
            self.assertEqual(queue.get(job["id"], "lab")["rows"][0]["status"], "needs_review")
            self.assertEqual(execute.call_count, 1)

    def test_cancel_marks_pending_not_attempted_and_blocks_resume(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            saved = queue.control(job["id"], "lab", "cancel")
            self.assertEqual(saved["rows"][0]["status"], "cancelled")
            self.assertEqual(saved["rows"][0]["deleted"], "Not attempted")
            with self.assertRaises(ValueError):
                queue.start(job["id"], "lab", Mock(), Mock())

    def test_csv_retains_all_601_rows_and_step_outputs(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", " ".join(f"user{index}@example.com" for index in range(601)))
            job["rows"][-1].update(status="needs_review", output="Clear AD Phone Fields,Failed,Requires review")
            rows = list(csv.reader(io.StringIO(csv_bytes(job).decode("utf-8-sig"))))
            self.assertEqual(len(rows), 602)
            self.assertEqual(rows[-1][0], "user600@example.com")
            self.assertIn("Clear AD Phone Fields", rows[-1][6])

    def test_history_retains_old_active_completed_and_cancelled_jobs_after_reload(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=181)).isoformat()
            with patch("toolkit.bulk_separation.now", return_value=old):
                queue._save(job)
            self.assertEqual(len(queue.history("lab")), 1)
            job["status"] = "completed"
            with patch("toolkit.bulk_separation.now", return_value=old):
                queue._save(job)
            self.assertEqual(len(BulkSeparationQueue(root).history("lab")), 1)
            job["status"] = "cancelled"
            with patch("toolkit.bulk_separation.now", return_value=old):
                queue._save(job)
            self.assertEqual(len(BulkSeparationQueue(root).history("lab")), 1)
            self.assertTrue(queue._path(job["id"]).exists())

    def test_fresh_build_list_keeps_all_rows_and_shared_devices_are_not_build_targets(self):
        job = {"id": "saved", "host": "lab", "rows": [{"email": f"user{index}@example.com", "status": "deleted", "deleted": "Yes", "name": "=Employee", "userid": "employee", "selected": True,
            "target_snapshot": [{"device_name": "CSFa", "extension": "1000", "partition": "PT", "relationship": "associated"}, {"device_name": "CSFa", "extension": "1000", "partition": "PT", "relationship": "owner"}],
            "extensions": [{"extension": "1000", "partition": "PT"}],
            "devices": [{"device_name": "CSFshared", "extension": "1000", "partition": "PT", "relationship": "shared extension"}]} for index in range(601)]}
        records = list(csv.DictReader(io.StringIO(bulk_separation.fresh_build_csv_bytes(job).decode("utf-8-sig"))))
        self.assertEqual(len(records), 601)
        self.assertEqual(records[-1]["Email"], "user600@example.com")
        self.assertEqual(records[0]["Name"], "'=Employee")
        self.assertEqual(records[0]["Previous Jabber Devices (Reference Only)"], "CSFa")
        self.assertEqual(records[0]["Previous Extensions / Partitions (Reference Only)"], "1000/PT")
        self.assertEqual(records[0]["Review Details Available"], "Yes")
        self.assertIn("not a configuration or voicemail restore", records[0]["Fresh Build Note"])

    def test_older_job_fresh_build_export_marks_missing_review_details(self):
        job = {"id": "older", "host": "lab", "rows": [{"email": "old@example.com", "status": "failed"}]}
        records = list(csv.DictReader(io.StringIO(bulk_separation.fresh_build_csv_bytes(job).decode("utf-8-sig"))))
        self.assertEqual(records[0]["Review Details Available"], "No - older job did not capture review details")
        self.assertEqual(records[0]["Previous Jabber Devices (Reference Only)"], "")


class BulkSeparationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        names = {"_bulk_separation_resolve", "_bulk_separation_devices", "_bulk_separation_preview", "_bulk_separation_execute", "_bulk_separation_public", "bulk_separation_get_route", "bulk_separation_post_route", "bulk_separation_csv_route"}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        for node in nodes:
            node.decorator_list = []
        cls.code = compile(ast.Module(body=nodes, type_ignores=[]), "<bulk-integration>", "exec")

    def setUp(self):
        self.scope = {"Request": object, "Form": lambda value: value, "csv": csv, "io": io, "json": json, "bulk_separation": bulk_separation,
            "_sql_escape_literal": lambda value: value.replace("'", "''"),
            "_axl_execute_sql_rows": Mock(return_value=[]), "_to_bytes": lambda data: data,
            "_run_full_separation": Mock(return_value=(b"Step,Status,Details\nLookup User,Success,Found\nRemove Phone,Success,Removed\n", "result.csv")),
            "_append_audit_event": Mock(), "_require_admin_session": Mock(return_value=({"cucm_host": "lab"}, "admin")),
            "_resolve_cucm_credentials": Mock(return_value=("lab", "admin", "secret")),
            "JSONResponse": lambda content, status_code=200, headers=None: SimpleNamespace(content=content, status_code=status_code, headers=headers),
            "Response": lambda **kwargs: SimpleNamespace(**kwargs)}
        exec(self.code, self.scope)

    def test_batched_exact_email_lookup_and_ambiguity(self):
        emails = [f"user{index}@example.com" for index in range(150)]
        def execute(host, username, password, sql):
            return [{"mailid": email.upper(), "userid": email.split("@")[0]} for email in emails if "'" + email + "'" in sql]
        self.scope["_axl_execute_sql_rows"].side_effect = execute
        result = self.scope["_bulk_separation_resolve"]("lab", "admin", "secret", emails)
        self.assertEqual(len(result), 150)
        self.assertTrue(all(len(matches) == 1 for matches in result.values()))
        self.assertEqual(self.scope["_axl_execute_sql_rows"].call_count, 2)
        self.assertIn("LOWER(mailid) IN", self.scope["_axl_execute_sql_rows"].call_args.args[3])

    def test_device_verification_keeps_names_after_association_cleared(self):
        self.scope["_bulk_separation_devices"]("lab", "admin", "secret", "user", ["csfOld"])
        sql = self.scope["_axl_execute_sql_rows"].call_args.args[3]
        self.assertIn("OR d.name IN ('csfOld')", sql)
        self.assertIn("UPPER(d.name) LIKE 'CSF%'", sql)
        self.assertIn("owneruser.userid='user'", sql)
        self.assertIn("LIKE 'TAB%'", sql)

    def test_failed_email_batch_does_not_stop_later_batch(self):
        emails = [f"user{index}@example.com" for index in range(150)]
        self.scope["_axl_execute_sql_rows"].side_effect = [RuntimeError("provider failure"), [{"mailid": emails[-1], "userid": "last"}]]
        result = self.scope["_bulk_separation_resolve"]("lab", "admin", "secret", emails)
        self.assertIsNone(result[emails[0]])
        self.assertEqual(result[emails[-1]], [{"userid": "last"}])

    def test_remaining_device_or_verification_failure_never_claims_deleted(self):
        self.scope["_bulk_separation_resolve"] = lambda *args: {"a@example.com": [{"userid": "a"}]}
        for verification, expected in [(["CSFa"], "No"), (RuntimeError("provider failure"), "Unknown")]:
            self.scope["_bulk_separation_devices"] = Mock(side_effect=[["CSFa"], verification])
            result = self.scope["_bulk_separation_execute"]("lab", "admin", "secret", "operator", "a@example.com", "a")
            self.assertEqual(result["deleted"], expected)
            self.assertEqual(result["status"], "needs_review")

    def test_full_process_warning_is_not_success_even_if_jabber_removed(self):
        self.scope["_bulk_separation_resolve"] = lambda *args: {"a@example.com": [{"userid": "a"}]}
        self.scope["_bulk_separation_devices"] = Mock(side_effect=[["CSFa"], []])
        self.scope["_run_full_separation"].return_value = (b"Step,Status,Details\nLookup User,Success,Found\nClear AD Phone Fields,Failed,RawProviderBody\n", "x.csv")
        result = self.scope["_bulk_separation_execute"]("lab", "admin", "secret", "operator", "a@example.com", "a")
        self.assertEqual(result["deleted"], "Yes")
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("Clear AD Phone Fields", result["detail"])
        self.assertNotIn("RawProviderBody", result["output"])

    def test_changed_identity_blocks_all_mutations(self):
        self.scope["_bulk_separation_resolve"] = lambda *args: {"a@example.com": [{"userid": "other"}]}
        result = self.scope["_bulk_separation_execute"]("lab", "admin", "secret", "operator", "a@example.com", "a")
        self.assertEqual(result["status"], "lookup_failed")
        self.scope["_run_full_separation"].assert_not_called()

    def test_changed_reviewed_devices_block_all_mutations(self):
        self.scope["_bulk_separation_resolve"] = lambda *args: {"a@example.com": [{"userid": "a"}]}
        with patch.object(bulk_separation, "target_inventory", return_value={"a": {"target_snapshot": [{"device_name": "new"}], "extensions": []}}):
            result = self.scope["_bulk_separation_execute"]("lab", "admin", "secret", "operator", "a@example.com", "a", {"target_snapshot": [], "extensions": []})
        self.assertEqual(result["deleted"], "Not attempted")
        self.assertEqual(result["status"], "needs_review")
        self.scope["_run_full_separation"].assert_not_called()

    def test_submit_route_only_starts_read_only_review(self):
        queue = Mock()
        queue.submit.return_value = {"id": "new", "rows": []}
        queue.get.return_value = {"id": "new", "rows": [], "status": "reviewing"}
        self.scope["BULK_SEPARATION_QUEUE"] = queue
        result = self.scope["bulk_separation_post_route"](object(), "submit", "", "a@example.com", "")
        self.assertEqual(result.status_code, 200)
        queue.review.assert_called_once()
        queue.start.assert_not_called()
        self.scope["_run_full_separation"].assert_not_called()

    def test_selected_route_approval_only_executes_saved_selection_and_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            self.scope["BULK_SEPARATION_QUEUE"] = queue
            job = queue.submit("lab", "admin", "a@example.com b@example.com")
            queue.review(job["id"], "lab", lambda emails: {email: {"userid": email, "eligible": True, "target_snapshot": [], "extensions": []} for email in emails})
            queue.worker.join(5)
            saved = queue.get(job["id"], "lab")
            selection = self.scope["bulk_separation_post_route"](object(), "select", job["id"], "", "", saved["selection_revision"], json.dumps(["a@example.com"]))
            self.assertEqual(selection.status_code, 200)
            self.scope["_bulk_separation_resolve"] = lambda *args: {email: [{"userid": email}] for email in args[-1]}
            execute = Mock(return_value={"status": "deleted"})
            self.scope["_bulk_separation_execute"] = execute
            result = self.scope["bulk_separation_post_route"](object(), "approve", job["id"], "", "DELETE", selection.content["selection_revision"], "[]")
            self.assertEqual(result.status_code, 200)
            queue.worker.join(5)
            execute.assert_called_once()
            self.assertEqual(execute.call_args.args[4:6], ("a@example.com", "a@example.com"))
            self.assertEqual(execute.call_args.args[6]["target_snapshot"], [])
            self.assertEqual(queue.get(job["id"], "lab")["approved_count"], 1)
            self.assertEqual(queue.get(job["id"], "lab")["rows"][1]["status"], "kept")

    def test_legacy_resume_cannot_bypass_new_review_requirement(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            self.scope["BULK_SEPARATION_QUEUE"] = queue
            job = queue.submit("lab", "admin", "a@example.com")
            result = self.scope["bulk_separation_post_route"](object(), "resume", job["id"], "", "DELETE")
            self.assertEqual(result.status_code, 409)
            self.scope["_run_full_separation"].assert_not_called()

    def test_review_preview_uses_batch_registration_without_phone_fallback(self):
        self.scope["_bulk_separation_resolve"] = Mock(return_value={})
        self.scope["_lookup_jabber_registration_statuses"] = Mock(return_value={})
        def build(emails, identities, read_sql, registrations):
            registrations(["CSFa", "SEPa"])
            return {}
        with patch.object(bulk_separation, "build_review", side_effect=build):
            self.scope["_bulk_separation_preview"]("lab", "admin", "secret", ["a@example.com"])
        self.scope["_lookup_jabber_registration_statuses"].assert_called_once_with("lab", "admin", "secret", ["CSFa", "SEPa"], allow_phone_fallback=False)

    def test_all_routes_require_admin_and_confirmation_before_mutation(self):
        self.scope["BULK_SEPARATION_QUEUE"] = Mock()
        self.scope["_require_admin_session"].side_effect = RuntimeError("Not admin")
        for name, args in [("bulk_separation_get_route", (object(),)), ("bulk_separation_post_route", (object(),)), ("bulk_separation_csv_route", (object(), "a"))]:
            self.assertEqual(self.scope[name](*args).status_code, 403)
        self.scope["BULK_SEPARATION_QUEUE"].submit.assert_not_called()
        self.scope["_require_admin_session"].side_effect = None
        result = self.scope["bulk_separation_post_route"](object(), "approve", "job", "", "")
        self.assertEqual(result.status_code, 409)
        self.scope["BULK_SEPARATION_QUEUE"].submit.assert_not_called()

    def test_public_preview_is_capped_but_counts_cover_entire_report(self):
        job = {"id": "abc", "rows": [{"status": "deleted", "deleted": "Yes", "output": "private step output"} for index in range(601)]}
        result = self.scope["_bulk_separation_public"](job)
        self.assertEqual(len(result["rows"]), 500)
        self.assertEqual(result["deleted_count"], 601)
        self.assertNotIn("output", result["rows"][0])
        job["status"] = "awaiting_review"
        self.assertEqual(len(self.scope["_bulk_separation_public"](job)["rows"]), 601)

    def test_saved_history_exposes_all_jobs_and_no_expiry_without_credentials(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            self.scope["BULK_SEPARATION_QUEUE"] = queue
            first = queue.submit("lab", "admin", "a@example.com")
            first["status"] = "completed"
            old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)).isoformat()
            with patch("toolkit.bulk_separation.now", return_value=old):
                queue._save(first)
            second = queue.submit("lab", "admin", "b@example.com")
            result = self.scope["bulk_separation_get_route"](object())
            self.assertEqual(result.status_code, 200)
            self.assertIsNone(result.content["retention_days"])
            self.assertEqual({job["id"] for job in result.content["jobs"]}, {first["id"], second["id"]})
            self.scope["_resolve_cucm_credentials"].assert_not_called()

    def test_fresh_build_download_uses_saved_host_scoped_job_without_provider_reads(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            self.scope["BULK_SEPARATION_QUEUE"] = queue
            job = queue.submit("lab", "admin", "a@example.com")
            result = self.scope["bulk_separation_csv_route"](object(), job["id"], True)
            self.assertIn("bulk_separation_fresh_build_", result.headers["Content-Disposition"])
            self.assertIn("a@example.com", result.content.decode("utf-8-sig"))
            self.assertIn("Fresh Build Note", result.content.decode("utf-8-sig"))
            self.scope["_require_admin_session"].return_value = ({"cucm_host": "prod"}, "admin")
            self.assertEqual(self.scope["bulk_separation_csv_route"](object(), job["id"], True).status_code, 409)
            self.scope["_require_admin_session"].side_effect = RuntimeError("Not admin")
            self.assertEqual(self.scope["bulk_separation_csv_route"](object(), job["id"], True).status_code, 403)
            self.scope["_resolve_cucm_credentials"].assert_not_called()
            self.scope["_axl_execute_sql_rows"].assert_not_called()


class BulkReviewInventoryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE enduser (pkid TEXT, userid TEXT, firstname TEXT, lastname TEXT, displayname TEXT);
            CREATE TABLE enduserdevicemap (fkenduser TEXT, fkdevice TEXT);
            CREATE TABLE device (pkid TEXT, name TEXT, fkenduser TEXT);
            CREATE TABLE devicenumplanmap (fkdevice TEXT, fknumplan TEXT);
            CREATE TABLE numplan (pkid TEXT, dnorpattern TEXT, fkroutepartition TEXT);
            CREATE TABLE routepartition (pkid TEXT, name TEXT);
            CREATE TABLE endusernumplanmap (fkenduser TEXT, fknumplan TEXT, tkdnusage INTEGER);
            INSERT INTO enduser VALUES ('ua','a','Alice','Example','Alice Example'), ('ub','b','Bob','Keep','Bob Keep');
            INSERT INTO routepartition VALUES ('rp1','ENT_DEVICE_PT'),('rp2','OTHER_PT');
            INSERT INTO numplan VALUES ('n1','1000','rp1'),('n2','2000','rp1'),('n3','1000','rp2');
            INSERT INTO device VALUES ('da','csfa','ua'),('dm','BOTa','ua'),('ds','SEPshared','ub'),('do','SEPotherpartition','ub'),('db','CSFb','ub');
            INSERT INTO enduserdevicemap VALUES ('ua','da'),('ua','dm'),('ub','db');
            INSERT INTO devicenumplanmap VALUES ('da','n1'),('dm','n1'),('ds','n1'),('do','n3'),('db','n2');
            INSERT INTO endusernumplanmap VALUES ('ua','n1',1),('ub','n2',1);
        """)
        self.queries = []
        self.registration = Mock(return_value={"csfa": {"status": "Registered"}, "BOTa": {"status": "Unregistered"}})

    def read_sql(self, sql):
        self.queries.append(sql)
        match = re.match(r"SELECT SKIP (\d+) FIRST (\d+) ", sql)
        self.assertIsNotNone(match)
        offset, limit = match.groups()
        return [dict(row) for row in self.db.execute("SELECT " + sql[match.end():] + f" LIMIT {limit} OFFSET {offset}")]

    def review(self, reader=None):
        return bulk_separation.build_review(["a@example.com"], {"a@example.com": [{"userid": "a"}]}, reader or self.read_sql, self.registration)["a@example.com"]

    def test_all_shared_extension_devices_names_partitions_and_live_registration(self):
        row = self.review()
        self.assertEqual(row["name"], "Alice Example")
        self.assertTrue(row["eligible"])
        self.assertEqual({line["device_name"] for line in row["devices"]}, {"csfa", "BOTa", "SEPshared", "SEPotherpartition"})
        states = {line["device_name"]: line["registration"] for line in row["devices"]}
        self.assertEqual(states["csfa"], "Registered")
        self.assertEqual(states["BOTa"], "Unregistered")
        self.assertEqual(states["SEPshared"], "Unknown")
        self.assertTrue(any(line["partition"] == "OTHER_PT" for line in row["devices"]))
        self.assertEqual({line["device_name"] for line in row["target_snapshot"]}, {"csfa", "BOTa"})
        self.assertEqual(len(self.queries), 3)
        self.registration.assert_called_once()

    def test_registration_failure_is_unknown_not_unregistered(self):
        self.registration.side_effect = RuntimeError("RIS unavailable")
        row = self.review()
        self.assertTrue(row["eligible"])
        self.assertEqual({line["registration"] for line in row["devices"]}, {"Unknown"})

    def test_shared_extension_failure_blocks_selection_and_retains_identity(self):
        def reader(sql):
            if "FROM numplan n INNER JOIN" in sql:
                raise RuntimeError("denied")
            return self.read_sql(sql)
        row = self.review(reader)
        self.assertFalse(row["eligible"])
        self.assertEqual(row["name"], "Alice Example")
        self.assertIn("lookup failed", row["detail"])

    def test_more_than_100_users_are_batched_without_per_person_queries(self):
        self.db.executemany("INSERT INTO enduser VALUES (?, ?, ?, ?, ?)", [(f"p{index}", f"user{index}", "First", "Last", "First Last") for index in range(150)])
        inventory = bulk_separation.target_inventory([f"user{index}" for index in range(150)], self.read_sql)
        self.assertEqual(len(inventory), 150)
        self.assertEqual(len(self.queries), 4)

    def test_primary_extension_without_associated_device_still_finds_shared_devices(self):
        self.db.execute("DELETE FROM enduserdevicemap WHERE fkenduser='ua'")
        self.db.execute("UPDATE device SET fkenduser=NULL WHERE fkenduser='ua'")
        row = self.review()
        self.assertEqual(row["target_snapshot"], [])
        self.assertEqual(row["extensions"], [{"extension": "1000", "partition": "ENT_DEVICE_PT"}])
        self.assertEqual(len(row["devices"]), 4)

    def test_repeated_inventory_pages_fail_closed(self):
        rows = [{"device_name": str(index)} for index in range(1000)]
        with self.assertRaisesRegex(ValueError, "Repeated"):
            list(bulk_separation._paged_rows(lambda sql: rows, "device_name FROM device"))


if __name__ == "__main__":
    unittest.main()
import tempfile
import ast
import csv
import datetime
import io
import json
from pathlib import Path
import re
import sqlite3
import xml.etree.ElementTree as ET
import time
from xml.sax.saxutils import escape as xml_escape
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from toolkit import bulk_separation
from toolkit import ad_phone_fields
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

    def test_dead_read_only_review_worker_is_reported_instead_of_staying_reviewing(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            job.update(status="reviewing", review_required=True)
            queue._save(job)
            self.assertEqual(queue.get(job["id"], "lab")["status"], "review_failed")
            self.assertEqual(queue.get(job["id"], "lab")["rows"][0]["deleted"], "Not attempted")

    def test_intermediate_review_progress_is_durable_and_not_approvable(self):
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            entered, release = threading.Event(), threading.Event()
            snapshots = {"a@example.com": {"userid": "a", "name": "Resolved Employee", "eligible": True, "extensions": [{"extension": "1000", "partition": "PT"}], "devices": []}}
            def preview(emails):
                queue.review_progress(job["id"], "lab", "Checking current RIS registration", snapshots)
                entered.set()
                release.wait(5)
                return snapshots
            queue.review(job["id"], "lab", preview)
            try:
                self.assertTrue(entered.wait(5))
                saved = queue.get(job["id"], "lab")
                self.assertEqual(saved["status"], "reviewing")
                self.assertEqual(saved["rows"][0]["name"], "Resolved Employee")
                self.assertIn("RIS", queue._read(queue._path(job["id"]))["review_progress"])
                with self.assertRaises(ValueError):
                    queue.approve(job["id"], "lab", "", "admin")
            finally:
                release.set()
                queue.worker.join(5)
            self.assertEqual(queue.get(job["id"], "lab")["status"], "awaiting_review")

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
            "lookup_ad_identities_by_email": Mock(side_effect=lambda emails, auth, **kwargs: {"ok": True, "results": [{"input_email": email, "found": True, "samAccountName": email.split("@")[0]} for email in emails]}),
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
            return [{"userid": email.split("@")[0]} for email in emails if "'" + email.split("@")[0] + "'" in sql]
        self.scope["_axl_execute_sql_rows"].side_effect = execute
        result = self.scope["_bulk_separation_resolve"]("lab", "admin", "secret", emails)
        self.assertEqual(len(result), 150)
        self.assertTrue(all(len(matches) == 1 for matches in result.values()))
        self.assertEqual(self.scope["_axl_execute_sql_rows"].call_count, 2)
        self.assertEqual(self.scope["lookup_ad_identities_by_email"].call_count, 2)
        self.assertIn("LOWER(userid) IN", self.scope["_axl_execute_sql_rows"].call_args.args[3])

    def test_ldap_username_finds_cucm_user_even_without_mailid(self):
        email = "morgan.fedde@amnhealthcare.com"
        self.scope["lookup_ad_identities_by_email"].side_effect = None
        self.scope["lookup_ad_identities_by_email"].return_value = {"ok": True, "results": [{"input_email": email, "found": True, "samAccountName": "Morgan.Fedde"}]}
        self.scope["_axl_execute_sql_rows"].return_value = [{"userid": "Morgan.Fedde"}]
        result = self.scope["_bulk_separation_resolve"]("lab", "admin", "secret", [email])
        self.assertEqual(result[email], [{"userid": "Morgan.Fedde"}])
        sql = self.scope["_axl_execute_sql_rows"].call_args.args[3]
        self.assertIn("LOWER(userid) IN ('morgan.fedde')", sql)
        self.assertNotIn("mailid", sql)
        self.scope["lookup_ad_identities_by_email"].assert_called_once_with([email], {"username": "admin", "password": "secret"}, require_unique=True)

    def test_device_verification_keeps_names_after_association_cleared(self):
        self.scope["_bulk_separation_devices"]("lab", "admin", "secret", "user", ["csfOld"])
        sql = self.scope["_axl_execute_sql_rows"].call_args.args[3]
        self.assertIn("OR d.name IN ('csfOld')", sql)
        self.assertIn("UPPER(d.name) LIKE 'CSF%'", sql)
        self.assertIn("owneruser.userid='user'", sql)
        self.assertIn("LIKE 'TAB%'", sql)

    def test_ldap_failure_continues_later_batches_and_never_guesses_username(self):
        emails = [f"alias{index}@example.com" for index in range(150)]
        self.scope["lookup_ad_identities_by_email"].side_effect = [{"ok": False, "error": "LDAP failed"}, {"ok": True, "results": [{"input_email": email, "found": email == emails[-1], "samAccountName": "Actual.Username" if email == emails[-1] else ""} for email in emails[100:]]}]
        self.scope["_axl_execute_sql_rows"].return_value = [{"userid": "Actual.Username"}]
        result = self.scope["_bulk_separation_resolve"]("lab", "admin", "secret", emails)
        self.assertIsNone(result[emails[0]])
        self.assertEqual(result[emails[-1]], [{"userid": "Actual.Username"}])
        self.scope["_axl_execute_sql_rows"].assert_called_once()
        sql = self.scope["_axl_execute_sql_rows"].call_args.args[3]
        self.assertIn("'actual.username'", sql)
        self.assertNotIn("alias149", sql)

    def test_missing_ambiguous_or_incomplete_ldap_results_cannot_authorize_cucm_lookup(self):
        helper = self.scope["lookup_ad_identities_by_email"]
        helper.side_effect = None
        for records in ([{"input_email": "a@example.com", "found": False}], [{"input_email": "a@example.com", "found": True, "ambiguous": True, "samAccountName": "a"}], []):
            helper.return_value = {"ok": True, "results": records}
            result = self.scope["_bulk_separation_resolve"]("lab", "admin", "secret", ["a@example.com"])
            self.assertFalse(result["a@example.com"])
        self.scope["_axl_execute_sql_rows"].assert_not_called()

    def test_failed_email_batch_does_not_stop_later_batch(self):
        emails = [f"user{index}@example.com" for index in range(150)]
        self.scope["_axl_execute_sql_rows"].side_effect = [RuntimeError("provider failure"), [{"userid": "user149"}]]
        result = self.scope["_bulk_separation_resolve"]("lab", "admin", "secret", emails)
        self.assertIsNone(result[emails[0]])
        self.assertEqual(result[emails[-1]], [{"userid": "user149"}])

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
        def build(emails, identities, read_sql, registrations, **kwargs):
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
            CREATE TABLE numplan (pkid TEXT, dnorpattern TEXT, fkroutepartition TEXT, tkpatternusage INTEGER DEFAULT 2);
            CREATE TABLE routepartition (pkid TEXT, name TEXT);
            CREATE TABLE endusernumplanmap (fkenduser TEXT, fknumplan TEXT, tkdnusage INTEGER);
            INSERT INTO enduser VALUES ('ua','a','Alice','Example','Alice Example'), ('ub','b','Bob','Keep','Bob Keep');
            INSERT INTO routepartition VALUES ('rp1','ENT_DEVICE_PT'),('rp2','OTHER_PT');
            INSERT INTO numplan (pkid,dnorpattern,fkroutepartition) VALUES ('n1','1000','rp1'),('n2','2000','rp1'),('n3','1000','rp2');
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
        self.assertEqual(len(self.queries), 4)
        self.registration.assert_called_once()

    def test_registration_failure_is_unknown_not_unregistered(self):
        self.registration.side_effect = RuntimeError("RIS unavailable")
        row = self.review()
        self.assertTrue(row["eligible"])
        self.assertEqual({line["registration"] for line in row["devices"]}, {"Unknown"})

    def test_never_registration_evidence_survives_saved_review_and_csv(self):
        self.registration.return_value = {"csfa": {"status": "Never", "last_registered": "Never", "history_status": "Never", "source": "cucm_registration_history"}}
        row = self.review()
        with tempfile.TemporaryDirectory() as root:
            queue = BulkSeparationQueue(root)
            job = queue.submit("lab", "admin", "a@example.com")
            job["rows"][0].update(row)
            queue._save(job)
            restored = BulkSeparationQueue(root).get(job["id"], "lab")
            device = next(line for line in restored["rows"][0]["devices"] if line["device_name"] == "csfa")
            self.assertEqual(device["registration"], "Never")
            self.assertEqual(device["last_registered"], "Never")
            self.assertEqual(device["registration_source"], "cucm_registration_history")
            output = next(csv.DictReader(io.StringIO(bulk_separation.csv_bytes(restored).decode("utf-8-sig"))))
            self.assertIn("Last registered: Never", output["Devices / Registration"])

    def test_exact_extension_translation_pattern_yes_and_no(self):
        self.assertEqual(self.review()["translation_pattern"], "No")
        self.db.execute("INSERT INTO numplan VALUES ('tp1','1000','rp2',3)")
        row = self.review()
        self.assertEqual(row["translation_pattern"], "Yes")
        self.assertEqual(row["translation_pattern_matches"], [{"extension": "1000", "partition": "OTHER_PT"}])
        self.assertEqual(row["extensions"], [{"extension": "1000", "partition": "ENT_DEVICE_PT"}])

    def test_translation_pattern_check_does_not_match_prefix_or_dn(self):
        self.db.execute("INSERT INTO numplan VALUES ('tp2','10001','rp2',15)")
        self.assertEqual(self.review()["translation_pattern"], "No")
        self.db.execute("INSERT INTO numplan VALUES ('tp3','1000','rp2',15)")
        self.assertEqual(self.review()["translation_pattern"], "Yes")

    def test_translation_pattern_failure_is_not_no(self):
        def reader(sql):
            if "tkpatternusage IN (3,15)" in sql:
                raise RuntimeError("query denied")
            return self.read_sql(sql)
        row = self.review(reader)
        self.assertEqual(row["translation_pattern"], "Lookup Failed")
        self.assertTrue(row["eligible"])

    def test_translation_pattern_evidence_is_in_both_saved_exports(self):
        self.db.execute("INSERT INTO numplan VALUES ('tp1','1000','rp2',3)")
        row = self.review()
        job = {"id": "saved", "host": "lab", "rows": [{**row, "email": "a@example.com", "status": "pending"}]}
        for exporter in (bulk_separation.csv_bytes, bulk_separation.fresh_build_csv_bytes):
            record = next(csv.DictReader(io.StringIO(exporter(job).decode("utf-8-sig"))))
            self.assertEqual(record["Extension Is Translation Pattern"], "Yes")
            self.assertEqual(record["Translation Pattern Matches"], "1000/OTHER_PT")
            self.assertTrue(record["Translation Pattern Checked At"])

    def test_review_publishes_people_and_devices_before_registration_finishes(self):
        progress = Mock()
        def registrations(names):
            stage, snapshots = progress.call_args.args
            self.assertIn("Checking current RIS", stage)
            self.assertEqual(snapshots["a@example.com"]["name"], "Alice Example")
            self.assertTrue(snapshots["a@example.com"]["devices"])
            self.assertEqual(snapshots["a@example.com"]["devices"][0]["registration"], "Checking RIS")
            return {}
        result = bulk_separation.build_review(["a@example.com"], {"a@example.com": [{"userid": "a"}]}, self.read_sql, registrations, progress=progress)
        self.assertEqual(result["a@example.com"]["devices"][0]["registration"], "Unknown")

    def test_two_email_aliases_for_same_employee_do_not_authorize_two_separations(self):
        result = bulk_separation.build_review(["a@example.com", "alias@example.com"], {"a@example.com": [{"userid": "a"}], "alias@example.com": [{"userid": "a"}]}, self.read_sql, self.registration)
        self.assertTrue(result["a@example.com"]["eligible"])
        self.assertFalse(result["alias@example.com"]["eligible"])
        self.assertIn("Duplicate verified employee", result["alias@example.com"]["detail"])

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


class RegistrationLookupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        names = {"_lookup_device_registration_history", "_lookup_jabber_registration_statuses"}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        cls.code = compile(ast.Module(body=nodes, type_ignores=[]), "<registration-lookup>", "exec")

    def setUp(self):
        self.sql = Mock(return_value=[{"device_name": "CSF9453753192", "history_timestamp": "", "history_ucm": "", "history_device_id": ""}])
        self.session = Mock()
        self.scope = {"_axl_execute_sql_rows": self.sql, "_sql_escape_literal": lambda value: value.replace("'", "''"), "json": json,
            "_greenlight_reg_display": lambda value: f"timestamp:{value}", "requests": SimpleNamespace(Session=Mock(return_value=self.session)),
            "HTTPBasicAuth": lambda *args: None, "_axl_list_process_nodes": Mock(return_value=["cucm"]),
            "ET": ET, "re": re, "DASHBOARD_REQUEST_TIMEOUT_SECONDS": 5,
            "_axl_post_raw_text": Mock(side_effect=RuntimeError("No fallback permitted"))}
        self.scope.update(time=time, xml_escape=xml_escape, _axl_local_name=lambda tag: tag.split("}")[-1],
            _find_xml_child=lambda node, name: next((child for child in node if child.tag.split("}")[-1] == name), None),
            _find_xml_child_text=lambda node, name: next((child.text or "" for child in node if child.tag.split("}")[-1] == name), ""))
        exec(self.code, self.scope)

    def test_morgan_never_returns_without_ris_or_getphone(self):
        result = self.scope["_lookup_jabber_registration_statuses"]("cucm", "admin", "secret", ["CSF9453753192"])
        self.assertEqual(result["CSF9453753192"]["status"], "Never")
        self.assertEqual(result["CSF9453753192"]["last_registered"], "Never")
        self.session.post.assert_not_called()
        self.scope["_axl_list_process_nodes"].assert_not_called()
        self.scope["_axl_post_raw_text"].assert_not_called()

    def test_missing_failed_or_malformed_history_is_unknown_not_never(self):
        for response in ([], [{"device_name": "CSF9453753192"}], RuntimeError("Permission denied")):
            self.sql.side_effect = response if isinstance(response, Exception) else None
            self.sql.return_value = response
            result = self.scope["_lookup_device_registration_history"]("cucm", "admin", "secret", ["CSF9453753192"])
            self.assertEqual(result["CSF9453753192"]["history_status"], "Unknown")

    def test_latest_valid_registration_history_wins_over_blank_record(self):
        self.sql.return_value = [{"device_name": "csf9453753192", "history_timestamp": "", "history_ucm": "", "history_device_id": ""},
            {"device_name": "csf9453753192", "history_timestamp": "1700000000", "history_ucm": "node1", "history_device_id": "device1"},
            {"device_name": "csf9453753192", "history_timestamp": "1750000000000", "history_ucm": "node2", "history_device_id": "device1"}]
        result = self.scope["_lookup_device_registration_history"]("cucm", "admin", "secret", ["CSF9453753192"])
        self.assertEqual(result["CSF9453753192"]["history_status"], "Previously Registered")
        self.assertEqual(result["CSF9453753192"]["last_registered_epoch"], 1750000000)

    def test_previously_registered_device_uses_live_ris_and_preserves_history(self):
        self.sql.return_value = [{"device_name": "CSF9453753192", "history_timestamp": "1750000000", "history_ucm": "node", "history_device_id": "device"}]
        self.session.post.return_value = SimpleNamespace(status_code=200, text="<result><CmNodes><item><ReturnCode>Ok</ReturnCode><CmDevices><item><Name>CSF9453753192</Name><Status>Registered</Status></item></CmDevices></item></CmNodes></result>")
        result = self.scope["_lookup_jabber_registration_statuses"]("cucm", "admin", "secret", ["CSF9453753192"])
        self.assertEqual(result["CSF9453753192"]["status"], "Registered")
        self.assertEqual(result["CSF9453753192"]["last_registered_epoch"], 1750000000)
        self.session.post.assert_called_once()
        self.assertNotIn("<ris:Item>*", self.session.post.call_args.kwargs["data"].decode())

    def test_successful_empty_ris_stops_retries_and_is_not_never(self):
        self.sql.return_value = []
        self.session.post.return_value = SimpleNamespace(status_code=200, text="<result><CmNodes/></result>")
        result = self.scope["_lookup_jabber_registration_statuses"]("cucm", "admin", "secret", ["CSF9453753192"])
        self.assertEqual(result["CSF9453753192"]["status"], "Unknown")
        self.session.post.assert_called_once()
        self.scope["_axl_post_raw_text"].assert_not_called()

    def test_registration_history_batches_150_devices_and_never_uses_per_device_reads(self):
        names = [f"CSF{index}" for index in range(150)]
        def execute(host, username, password, sql):
            return [{"device_name": name, "history_timestamp": "", "history_ucm": "", "history_device_id": ""} for name in names if "'" + name.lower() + "'" in sql]
        self.sql.side_effect = execute
        result = self.scope["_lookup_jabber_registration_statuses"]("cucm", "admin", "secret", names)
        self.assertEqual(len(result), 150)
        self.assertTrue(all(record["status"] == "Never" for record in result.values()))
        self.assertEqual(self.sql.call_count, 2)
        self.session.post.assert_not_called()

    def test_ris_time_budget_exhaustion_does_not_trigger_fallbacks(self):
        self.sql.return_value = []
        self.scope["time"] = SimpleNamespace(monotonic=Mock(side_effect=[0, 25]))
        result = self.scope["_lookup_jabber_registration_statuses"]("cucm", "admin", "secret", ["CSF9453753192"])
        self.assertEqual(result["CSF9453753192"]["status"], "Unknown")
        self.session.post.assert_not_called()
        self.scope["_axl_post_raw_text"].assert_not_called()

    def test_node_discovery_failure_still_checks_selected_host(self):
        self.sql.return_value = []
        self.scope["_axl_list_process_nodes"].side_effect = RuntimeError("Node inventory unavailable")
        self.session.post.return_value = SimpleNamespace(status_code=200, text="<result><CmNodes/></result>")
        result = self.scope["_lookup_jabber_registration_statuses"]("cucm", "admin", "secret", ["CSF9453753192"])
        self.assertEqual(result["CSF9453753192"]["status"], "Unknown")
        self.assertTrue(self.session.post.call_args.args[0].startswith("https://cucm:"))


class PersonLiveRegistrationRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "lookup_person_route")
        node.decorator_list = []
        cls.code = compile(ast.Module(body=[node], type_ignores=[]), "<person-live-route>", "exec")

    def setUp(self):
        self.registration = Mock(return_value={"CSF9453753192": {"status": "Never", "last_registered": "Never", "history_status": "Never", "source": "cucm_registration_history"}})
        self.search = Mock(return_value=[{"userid": "Morgan.Fedde", "devices": [{"name": "CSF9453753192", "status": "Registered"}]}])
        self.credentials = Mock(return_value=("selected-cucm", "admin", "secret"))
        self.scope = {"Request": object, "Form": lambda value: value, "_resolve_cucm_credentials": self.credentials,
            "_update_cached_credentials": Mock(), "search_persons_by_name": self.search,
            "_lookup_jabber_registration_statuses": self.registration,
            "JSONResponse": lambda content, status_code=200: SimpleNamespace(content=content, status_code=status_code)}
        exec(self.code, self.scope)

    def test_morgan_live_check_returns_json_never_even_when_cached_status_exists(self):
        response = self.scope["lookup_person_route"](object(), last_name="Fedde", first_name="M", include_jabber_registration="on")
        self.assertEqual(response.status_code, 200)
        self.registration.assert_called_once_with("selected-cucm", "admin", "secret", ["CSF9453753192"])
        person = response.content["results"][0]
        self.assertEqual(person["devices"][0]["registration_status"], "Never")
        self.assertEqual(person["devices"][0]["last_registered"], "Never")
        self.assertIn("1 Never", person["jabber_registration_summary"])

    def test_unchecked_live_registration_keeps_existing_fast_lookup(self):
        response = self.scope["lookup_person_route"](object(), last_name="Fedde")
        self.assertTrue(response.content["ok"])
        self.registration.assert_not_called()

    def test_expired_session_and_lookup_failure_return_json_not_html(self):
        self.credentials.side_effect = RuntimeError("Session credentials expired. Please log in again.")
        response = self.scope["lookup_person_route"](object(), last_name="Fedde", include_jabber_registration="on")
        self.assertEqual(response.status_code, 401)
        self.assertIn("log in again", response.content["error"]["message"])
        self.credentials.side_effect = None
        self.search.side_effect = RuntimeError("raw provider secret response")
        response = self.scope["lookup_person_route"](object(), last_name="Fedde", include_jabber_registration="on")
        self.assertEqual(response.status_code, 502)
        self.assertFalse(response.content["ok"])
        self.assertNotIn("secret", str(response.content))


class BulkLdapIdentityTests(unittest.TestCase):
    def entry(self, sam, mail, aliases=()):
        return SimpleNamespace(sAMAccountName=SimpleNamespace(value=sam), mail=SimpleNamespace(value=mail),
            userPrincipalName=SimpleNamespace(value=mail), givenName=SimpleNamespace(value="First"), sn=SimpleNamespace(value="Last"),
            proxyAddresses=SimpleNamespace(values=list(aliases)))

    def lookup(self, entries, emails, result_code=0, strict=True):
        connection = Mock(entries=entries, result={"result": result_code})
        config = {"server": "ldap.example.com", "port": 636, "use_ssl": True, "base_dn": "dc=example,dc=com"}
        with patch.multiple(ad_phone_fields, LDAP3_AVAILABLE=True, Server=Mock(), Connection=Mock(return_value=connection), ALL="all", SUBTREE="subtree", create=True), patch.object(ad_phone_fields, "_resolve_ldap_config", return_value=(config, "")), patch.object(ad_phone_fields, "_resolve_ldap_bind_credentials", return_value=("admin", "SIMPLE", "")):
            return ad_phone_fields.lookup_ad_identities_by_email(emails, {"username": "admin", "password": "secret"}, require_unique=strict)

    def test_unique_alias_is_matched_once_and_duplicate_directory_identities_are_refused(self):
        entries = [self.entry("Morgan.Fedde", "primary@example.com", ["SMTP:morgan.fedde@example.com"])]
        result = self.lookup(entries, ["morgan.fedde@example.com", "primary@example.com"])
        self.assertTrue(all(row["found"] for row in result["results"]))
        entries.append(self.entry("Other.User", "other@example.com", ["smtp:morgan.fedde@example.com"]))
        ambiguous = self.lookup(entries, ["morgan.fedde@example.com"])
        self.assertFalse(ambiguous["results"][0]["found"])
        self.assertTrue(ambiguous["results"][0]["ambiguous"])

    def test_incomplete_ldap_search_is_not_a_successful_empty_lookup(self):
        result = self.lookup([], ["a@example.com"], result_code=4)
        self.assertFalse(result["ok"])

    def test_existing_callers_keep_default_non_strict_behavior(self):
        entries = [self.entry("First", "a@example.com"), self.entry("Second", "a@example.com")]
        result = self.lookup(entries, ["a@example.com"], strict=False)
        self.assertTrue(result["results"][0]["found"])
        self.assertEqual(result["results"][0]["samAccountName"], "Second")

    def test_ldapsearch_fallback_refuses_multiple_directory_matches(self):
        config = {"server": "ldap.example.com", "port": 636, "use_ssl": True, "base_dn": "dc=example,dc=com"}
        with patch.object(ad_phone_fields, "LDAP3_AVAILABLE", False), patch.object(ad_phone_fields, "_resolve_ldap_config", return_value=(config, "")), patch.object(ad_phone_fields, "_resolve_ldap_bind_credentials", return_value=("admin", "SIMPLE", "")), patch.object(ad_phone_fields, "_resolve_ldapsearch_bind_user", return_value="admin"), patch.object(ad_phone_fields, "_run_ldapsearch_query", return_value=({"dn": ["cn=First", "cn=Second"], "sAMAccountName": ["First", "Second"]}, "")):
            result = ad_phone_fields.lookup_ad_identities_by_email(["a@example.com"], {"password": "secret"}, require_unique=True)
        self.assertFalse(result["results"][0]["found"])
        self.assertTrue(result["results"][0]["ambiguous"])


if __name__ == "__main__":
    unittest.main()
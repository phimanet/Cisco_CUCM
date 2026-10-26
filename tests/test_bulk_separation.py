import tempfile
import ast
import csv
import datetime
import io
from pathlib import Path
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from toolkit.bulk_separation import BulkSeparationQueue, csv_bytes, parse_emails


class BulkSeparationTests(unittest.TestCase):
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

    def test_retention_never_prunes_active_jobs_or_other_recent_reports(self):
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
            self.assertEqual(queue.history("lab"), [])


class BulkSeparationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        names = {"_bulk_separation_resolve", "_bulk_separation_devices", "_bulk_separation_execute", "_bulk_separation_public", "bulk_separation_get_route", "bulk_separation_post_route", "bulk_separation_csv_route"}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        for node in nodes:
            node.decorator_list = []
        cls.code = compile(ast.Module(body=nodes, type_ignores=[]), "<bulk-integration>", "exec")

    def setUp(self):
        self.scope = {"Request": object, "Form": lambda value: value, "csv": csv, "io": io,
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

    def test_all_routes_require_admin_and_confirmation_before_mutation(self):
        self.scope["BULK_SEPARATION_QUEUE"] = Mock()
        self.scope["_require_admin_session"].side_effect = RuntimeError("Not admin")
        for name, args in [("bulk_separation_get_route", (object(),)), ("bulk_separation_post_route", (object(),)), ("bulk_separation_csv_route", (object(), "a"))]:
            self.assertEqual(self.scope[name](*args).status_code, 403)
        self.scope["BULK_SEPARATION_QUEUE"].submit.assert_not_called()
        self.scope["_require_admin_session"].side_effect = None
        result = self.scope["bulk_separation_post_route"](object(), "submit", "", "a@example.com", "")
        self.assertEqual(result.status_code, 409)
        self.scope["BULK_SEPARATION_QUEUE"].submit.assert_not_called()

    def test_public_preview_is_capped_but_counts_cover_entire_report(self):
        job = {"id": "abc", "rows": [{"status": "deleted", "deleted": "Yes", "output": "private step output"} for index in range(601)]}
        result = self.scope["_bulk_separation_public"](job)
        self.assertEqual(len(result["rows"]), 500)
        self.assertEqual(result["deleted_count"], 601)
        self.assertNotIn("output", result["rows"][0])


if __name__ == "__main__":
    unittest.main()
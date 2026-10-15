import ast
import csv
import io
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from toolkit import voicemail_box_cleanup as cleanup


class VoicemailCleanupTests(unittest.TestCase):
    def start(self, rows=None):
        executor = Mock(return_value=rows or [])
        state = cleanup.start("unity.example", "cucm.example", "operator", "secret", executor)
        return state, executor

    def advance(self, state, records, total=None):
        payload = {"User": records}
        if total is not None:
            payload["@total"] = str(total)
        with patch.object(cleanup.users, "_read_user_resource", return_value=payload):
            cleanup.advance(state, "operator", "secret")

    def person(self, identity="one", extension="1000"):
        return {"ObjectId": identity, "FirstName": "First", "LastName": "Last", "Alias": "first.last",
                "SmtpAddress": "first.last@example.com", "DtmfAccessId": extension}

    def test_exact_match_all_devices_partitions_and_missing_extension(self):
        state, executor = self.start([{"device_name": "BOTperson", "extension": "1000", "partition": "OTHER"},
                                      {"device_name": "CSFperson", "extension": "1000", "partition": "ENT_DEVICE_PT"}])
        self.advance(state, [self.person(), self.person("two", "71000"), self.person("three", "")], 3)
        self.assertEqual(state["status"], "completed")
        self.assertEqual([row["jabber_match"] for row in state["rows"]], ["Matching Jabber", "No matching Jabber", "No primary extension"])
        self.assertEqual(state["rows"][0]["email"], "first.last@example.com")
        self.assertEqual(state["rows"][0]["jabber_devices"], "BOTperson; CSFperson")
        sql = executor.call_args.args[-1]
        self.assertNotIn("numplanindex = 1", sql)
        self.assertIn("TAB%", sql)
        self.assertTrue(sql.startswith("SELECT "))
        self.assertEqual(executor.call_count, 1)

    def test_count_only_page_zero_and_restart(self):
        state, _ = self.start()
        with patch.object(cleanup.users, "_read_user_resource", return_value={"@total": "2"}):
            cleanup.advance(state, "operator", "secret")
        self.assertEqual(state["page"], 1)
        self.advance(state, [self.person()], 2)
        with tempfile.TemporaryDirectory() as root:
            cleanup.save(root, state)
            restored = cleanup.load(root, state["host"], state["cucm_host"])
            self.advance(restored, [self.person("two")], 2)
            self.assertEqual(len(restored["rows"]), 2)
            cleanup.save(root, cleanup.report(restored), "report")
            self.assertEqual(cleanup.load(root, state["host"], state["cucm_host"], "report")["status"], "completed")
            with self.assertRaises(FileNotFoundError):
                cleanup.load(root, state["host"], "other.example")

    def test_repeated_users_and_incomplete_counts_refused_without_appending(self):
        state, _ = self.start()
        self.advance(state, [self.person()], 3)
        for records, total in (([self.person()], 3), ([], 3), ([self.person("two")], 4)):
            with self.assertRaises(ValueError):
                self.advance(state, records, total)
            self.assertEqual(len(state["rows"]), 1)
        with patch.object(cleanup.users, "_read_user_resource", return_value={"@total": "3"}):
            with self.assertRaises(ValueError):
                cleanup.advance(state, "operator", "secret")

    def test_empty_inventory_and_paused_scan(self):
        state, _ = self.start()
        self.advance(state, [], 0)
        self.assertEqual(state["status"], "completed")
        state["status"] = "paused"
        with patch.object(cleanup.users, "_read_user_resource") as read:
            cleanup.advance(state, "", "")
            read.assert_not_called()

    def test_full_safe_csv_and_retention_after_failure(self):
        state, _ = self.start()
        records = [dict(self.person(str(index)), FirstName="=danger") for index in range(601)]
        self.advance(state, records, 601)
        report = cleanup.report(state)
        rows = list(csv.reader(io.StringIO(cleanup.csv_report(report))))
        self.assertEqual(len(rows), 602)
        self.assertEqual(rows[1][0], "'=danger")
        self.assertIn("completed", rows[1])
        with tempfile.TemporaryDirectory() as root:
            cleanup.save(root, report, "report")
            with patch.object(cleanup.storage.os, "replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    cleanup.save(root, dict(report, rows=[]), "report")
            self.assertEqual(len(cleanup.load(root, state["host"], state["cucm_host"], "report")["rows"]), 601)
            path = cleanup.storage._path(cleanup.pair_root(root, state["cucm_host"]), state["host"], "report")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("corrupt")
            with self.assertRaises(ValueError):
                cleanup.save(root, report, "report")

    def test_paged_inventory_no_per_mailbox_queries_and_failures(self):
        batches = [[{"device_name": "CSFone", "extension": "1000", "partition": "PT"}], []]
        with patch.object(cleanup, "PAGE_SIZE", 1):
            executor = Mock(side_effect=batches)
            state = cleanup.start("unity.example", "cucm.example", "operator", "secret", executor)
        self.advance(state, [self.person(str(index)) for index in range(200)], 200)
        self.assertEqual(executor.call_count, 2)
        with self.assertRaises(RuntimeError):
            cleanup.start("unity.example", "cucm.example", "operator", "secret", Mock(side_effect=RuntimeError("AXL failed")))

    def test_transport_is_get_only_and_count_errors_are_not_empty_success(self):
        state, _ = self.start()
        client = Mock()
        client.get.return_value = SimpleNamespace(status_code=200, json=lambda: {"@total": "1", "User": [self.person()]})
        cleanup.advance(state, "operator", "secret", client)
        self.assertEqual(client.get.call_count, 1)
        client.post.assert_not_called()
        self.assertFalse(client.get.call_args.kwargs["allow_redirects"])
        self.assertEqual(client.get.call_args.args[0], "https://unity.example/vmrest/users")
        state, _ = self.start()
        with self.assertRaises(cleanup.storage.UnitySearchError):
            with patch.object(cleanup.users, "_read_user_resource", return_value={"@total": "bad"}):
                cleanup.advance(state, "operator", "secret")


class VoicemailCleanupRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / "main.py"
        tree = ast.parse(source.read_text(encoding="utf-8-sig"))
        names = {"voicemail_cleanup_saved", "voicemail_cleanup_run"}
        cls.nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.access = Mock(return_value=("unity.example", {"cucm_host": "cucm.example", "username": "admin"}))
        self.sql = Mock(return_value=[])
        self.audit = Mock()

        def response(content, **kwargs):
            return SimpleNamespace(content=content, **kwargs)

        self.scope = {"Request": object, "Form": lambda value: value, "voicemail_box_cleanup": cleanup,
                      "unity_number_search": cleanup.storage, "VOICEMAIL_CLEANUP_DIR": self.directory.name,
                      "VOICEMAIL_CLEANUP_LOCK": threading.Lock(), "_unity_read_access": self.access,
                      "_resolve_unity_credentials": Mock(return_value=("operator", "secret")),
                      "_resolve_cucm_credentials": Mock(return_value=("cucm.example", "operator", "secret")),
                      "_axl_execute_sql_rows": self.sql, "_append_audit_event": self.audit,
                      "JSONResponse": response, "Response": response,
                      "_unity_search_failure": lambda error: SimpleNamespace(error=error)}
        for original in self.nodes:
            node = ast.FunctionDef(name=original.name, args=original.args, body=original.body,
                                   decorator_list=[], returns=original.returns, type_comment=None)
            exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), "main.py", "exec"), self.scope)
        self.request = SimpleNamespace(url=SimpleNamespace(path="/unity-connection/voicemail-box-cleanup/saved"))

    def run_action(self, action="start", job_id=""):
        return self.scope["voicemail_cleanup_run"](self.request, action, job_id)

    def test_admin_guard_applies_before_reads_and_download(self):
        self.access.side_effect = PermissionError("admin only")
        self.assertIsInstance(self.run_action().error, PermissionError)
        self.assertIsInstance(self.scope["voicemail_cleanup_saved"](self.request).error, PermissionError)
        self.sql.assert_not_called()

    def test_duplicate_stale_controls_resume_completion_and_download(self):
        report = self.run_action().content["report"]
        identity = report["job_id"]
        self.assertEqual(self.run_action().content["report"]["job_id"], identity)
        self.assertEqual(self.sql.call_count, 1)
        self.assertIsInstance(self.run_action("advance", "stale").error, ValueError)
        self.assertEqual(self.run_action("pause", identity).content["report"]["status"], "paused")
        self.assertEqual(self.run_action("resume", identity).content["report"]["status"], "running")
        with patch.object(cleanup.users, "_read_user_resource", return_value={"@total": "0", "User": []}):
            self.assertEqual(self.run_action("advance", identity).content["report"]["status"], "completed")
        saved = self.scope["voicemail_cleanup_saved"](self.request, "report")
        self.assertEqual(saved.content["report"]["status"], "completed")
        self.request.url.path = "/unity-connection/voicemail-box-cleanup/csv"
        self.assertIsInstance(self.scope["voicemail_cleanup_saved"](self.request, "report", "stale").error, ValueError)
        self.assertIn("First Name,Last Name,Email,Username,Extension", self.scope["voicemail_cleanup_saved"](self.request, "report", identity).content)
        self.assertIsInstance(self.run_action("delete", identity).error, ValueError)

    def test_read_failure_pauses_persisted_scan_and_keeps_prior_report(self):
        report = self.run_action().content["report"]
        old_report = dict(report, status="completed", job_id="old")
        cleanup.save(self.directory.name, old_report, "report")
        with patch.object(cleanup.users, "_read_user_resource", side_effect=RuntimeError("HTTP failure")):
            self.assertIsInstance(self.run_action("advance", report["job_id"]).error, RuntimeError)
        restored = cleanup.load(self.directory.name, "unity.example", "cucm.example")
        self.assertEqual(restored["status"], "paused")
        self.assertEqual(restored["page"], 0)
        self.assertEqual(cleanup.load(self.directory.name, "unity.example", "cucm.example", "report")["job_id"], "old")
        self.assertEqual(self.run_action("cancel", report["job_id"]).content["report"]["status"], "cancelled")
        self.assertIsInstance(self.run_action("resume", report["job_id"]).error, ValueError)


if __name__ == "__main__":
    unittest.main()
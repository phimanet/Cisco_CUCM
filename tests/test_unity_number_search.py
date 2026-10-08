import ast
import json
import tempfile
import threading
import unittest
from html import escape
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from toolkit import unity_number_search as search


class UnityNumberSearchTests(unittest.TestCase):
    def test_transfer_and_indirect_reference(self):
        owner = {"id": "sales", "name": "Sales", "type": "System Call Handler"}
        fields, edges = search.record_evidence({"Extension": "+1 (469) 706-1228", "Enabled": "false"}, owner, "/transferoptions/Alternate")
        source = {"id": "main", "name": "Main", "type": "System Call Handler"}
        _, link = search.record_evidence({"AfterGreetingTargetHandlerObjectId": "sales", "AfterGreetingAction": "2"}, source, "/greetings/Standard")
        state = {"query": "4697061228", "mode": "contains", "fields": fields, "edges": edges + link,
                 "objects": {"sales": owner, "main": source}}
        rows = search.find_matches(state)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["reference"] for row in rows}, {"Direct", "Indirect"})
        self.assertIn("Enabled=false", rows[1]["context"])
        state["mode"] = "exact"
        self.assertEqual(search.find_matches(state), [])

    def test_cycles_and_sensitive_fields(self):
        owner = {"id": "one", "name": "One", "type": "Handler"}
        fields, _ = search.record_evidence({"DtmfAccessId": "1228", "Password": "1228", "Pin": "1228", "Token": "1228", "URI": "/vmrest/users/1228"}, owner, "/one")
        state = {"query": "1228", "mode": "exact", "fields": fields, "objects": {"one": owner, "two": owner},
                 "edges": [{"source": "two", "target": "one", "field": "TargetHandlerObjectId", "resource": "/two", "context": ""},
                           {"source": "one", "target": "two", "field": "TargetHandlerObjectId", "resource": "/one", "context": ""}]}
        rows = search.find_matches(state)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["field"], "DtmfAccessId")

    def test_validation(self):
        self.assertEqual(search.normalize_query("+1 (469) 706-1228"), "14697061228")
        for value in ("12", "12%28", "abc1228", ""):
            with self.assertRaises(ValueError):
                search.normalize_query(value)

    def response(self, payload, code=200):
        response = MagicMock(status_code=code)
        response.json.return_value = payload
        return response

    def single_task(self):
        state = search.new_scan("unity.example", "1228")
        state["tasks"] = state["tasks"][:1]
        return state

    def test_paged_handler_and_child_discovery(self):
        state = self.single_task()
        client = MagicMock()
        client.get.side_effect = [self.response({"@total": "2", "Callhandler": {"ObjectId": "one", "URI": "/vmrest/handlers/callhandlers/one", "DisplayName": "One", "DtmfAccessId": "1228"}}),
                                  self.response({"@total": "2", "Callhandler": {"ObjectId": "two", "URI": "/vmrest/handlers/callhandlers/two", "DisplayName": "Two"}})]
        search.advance_scan(state, "admin", "SECRET", client)
        search.advance_scan(state, "admin", "SECRET", client)
        self.assertEqual(client.get.call_args_list[1].kwargs["params"]["pageNumber"], 1)
        self.assertIn("/vmrest/handlers/callhandlers/one/menuentries", state["scheduled"])
        self.assertIn("/vmrest/handlers/callhandlers/two/greetings", state["scheduled"])
        self.assertNotIn("SECRET", json.dumps(state))
        self.assertEqual(len(search.find_matches(state)), 1)
        client.post.assert_not_called()
        client.put.assert_not_called()
        client.delete.assert_not_called()

    def test_repeated_page_is_failed_not_empty(self):
        state = self.single_task()
        client = MagicMock()
        client.get.return_value = self.response({"@total": "2", "Callhandler": {"ObjectId": "one", "URI": "/vmrest/handlers/callhandlers/one"}})
        search.advance_scan(state, "admin", "pass", client)
        search.advance_scan(state, "admin", "pass", client)
        self.assertEqual(state["coverage"][0]["status"], "Failed")
        self.assertIn("repeated", state["coverage"][0]["detail"])

    def test_restart_does_not_repeat_completed_resource(self):
        state = self.single_task()
        client = MagicMock()
        client.get.return_value = self.response({"@total": "0"})
        search.advance_scan(state, "admin", "pass", client)
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            restored = search.load(root, "unity.example")
            search.advance_scan(restored, "admin", "pass", client)
        self.assertEqual(client.get.call_count, 1)
        self.assertEqual(restored["status"], "completed")

    def test_save_failure_and_corrupt_state_are_refused(self):
        state = self.single_task()
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            state["query"] = "9999"
            with patch.object(search.os, "replace", side_effect=OSError("full")):
                with self.assertRaises(OSError):
                    search.save(root, state)
            self.assertEqual(search.load(root, "unity.example")["query"], "1228")
            path = Path(search._path(root, "unity.example", "scan"))
            path.write_text("broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                search.save(root, state)
            self.assertEqual(path.read_text(encoding="utf-8"), "broken")

    def test_host_isolation_and_latest_report_retention(self):
        state = self.single_task()
        state["status"] = "completed"
        with tempfile.TemporaryDirectory() as root:
            report = search.scan_report(state)
            search.save(root, report, "report")
            failed = search.new_scan("unity.example", "9999")
            failed["status"] = "failed"
            search.save(root, failed)
            self.assertEqual(search.load(root, "unity.example", "report")["query"], "1228")
            with self.assertRaises(FileNotFoundError):
                search.load(root, "other.example", "report")

    def test_auth_failure_pauses_without_losing_task(self):
        state = self.single_task()
        client = MagicMock()
        client.get.return_value = self.response({}, 403)
        with self.assertRaises(search.UnitySearchError):
            search.advance_scan(state, "admin", "pass", client)
        self.assertEqual(state["status"], "paused")
        self.assertEqual(len(state["tasks"]), 1)

    def test_untrusted_and_sensitive_links(self):
        for resource in ("https://evil.example/vmrest/users", "/vmrest/users/one/password", "/vmrest/users/../users", "/vmrest/users?token=secret", "/vmrest/voicefiles/one"):
            with self.assertRaises(search.UnitySearchError):
                search.safe_resource(resource, "unity.example")
        self.assertEqual(search.safe_resource("/vmrest/handlers/callhandlers/one/transferoptions/Off%20Hours", "unity.example"), "/vmrest/handlers/callhandlers/one/transferoptions/Off%20Hours")

    def test_all_scalar_fields_and_nested_caller_input(self):
        owner = {"id": "one", "name": "One", "type": "Handler"}
        fields, _ = search.record_evidence({"Description": "Retired number 4697061228", "Inputs": [{"TransferNumber": "4697061228", "TouchtoneKey": "1"}], "CustomNumber": 4697061228}, owner, "/one")
        state = {"query": "4697061228", "mode": "exact", "fields": fields, "objects": {"one": owner}, "edges": []}
        self.assertEqual(len(search.find_matches(state)), 3)

    def test_failed_endpoint_does_not_claim_complete(self):
        state = self.single_task()
        client = MagicMock()
        client.get.return_value = self.response({}, 404)
        search.advance_scan(state, "admin", "pass", client)
        report = search.scan_report(state)
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["failures"]), 1)
        self.assertEqual(report["rows"], [])

    def test_user_primary_handler_uses_handler_identity(self):
        state = search.new_scan("unity.example", "1228")
        user_task = {"resource": "/vmrest/users", "owner": None, "label": "Users / mailboxes"}
        search._ingest(state, {"ObjectId": "user", "DisplayName": "User Name", "URI": "/vmrest/users/user",
                              "CallHandlerURI": "/vmrest/handlers/callhandlers/primary"}, user_task)
        handler_task = next(task for task in state["tasks"] if task["resource"] == "/vmrest/handlers/callhandlers/primary")
        self.assertEqual(handler_task["owner"]["id"], "primary")

    def test_each_indirect_caller_key_is_retained(self):
        owner = {"id": "sales", "name": "Sales", "type": "Handler"}
        fields, _ = search.record_evidence({"Extension": "1228"}, owner, "/sales")
        edges = [{"source": "main", "target": "sales", "field": "TargetHandlerObjectId", "resource": "/main/menuentries/" + key, "context": "Key=" + key} for key in ("1", "2")]
        state = {"query": "1228", "mode": "exact", "fields": fields, "edges": edges + edges,
                 "objects": {"sales": owner, "main": {"id": "main", "name": "Main", "type": "Handler"}}}
        rows = search.find_matches(state)
        self.assertEqual(len(rows), 3)
        self.assertEqual({row["context"] for row in rows if row["reference"] == "Indirect"}, {"Key=1", "Key=2"})


class UnitySearchRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8-sig"))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.session = {"username": "admin", "cucm_host": "lab"}
        self.audit = []
        def response(content=None, status_code=200, headers=None, **kwargs):
            return SimpleNamespace(content=content, body=json.dumps(content).encode(), status_code=status_code, headers=headers)
        self.scope = {"unity_number_search": search, "UNITY_NUMBER_SEARCH_DIR": self.directory.name,
                      "UNITY_NUMBER_SEARCH_LOCK": threading.Lock(), "json": json, "escape": escape,
                      "JSONResponse": response, "HTMLResponse": response, "Request": object,
                      "Form": lambda value: value, "_get_auth_session": lambda request: self.session,
                      "_is_admin_user": lambda user: user == "admin", "_get_unity_server_for_session": lambda request: "unity.example",
                      "_resolve_unity_credentials": lambda *args: ("admin", "SECRET"),
                      "_get_environment_label": lambda host: ("LAB", "lab"), "_append_audit_event": lambda **kwargs: self.audit.append(kwargs)}
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in {"MS_CALLING_PAGE_TEMPLATE", "UNITY_SEARCH_PAGE_BODY"} for target in node.targets):
                exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), self.scope)
            if isinstance(node, ast.FunctionDef) and (node.name.startswith("_unity_search_") or node.name.startswith("unity_search_") or node.name == "unity_connection_page"):
                node.decorator_list = []
                exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), self.scope)
        self.request = SimpleNamespace(url=SimpleNamespace(path="/unity-connection/search/scan"))

    def call(self, name, **kwargs):
        return self.scope[name](self.request, **kwargs)

    def test_all_routes_require_admin(self):
        self.session["username"] = "not-admin"
        for name, arguments in (("unity_connection_page", {}), ("unity_search_start", {"number": "1228"}),
                                ("unity_search_saved", {}), ("unity_search_advance", {"job_id": "one"}),
                                ("unity_search_control", {"job_id": "one", "action": "resume"})):
            self.assertEqual(self.call(name, **arguments).status_code, 403)

    def test_duplicate_stale_pause_resume_cancel(self):
        first = self.call("unity_search_start", number="1228").content["report"]
        second = self.call("unity_search_start", number="1228").content["report"]
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(self.call("unity_search_start", number="9999").status_code, 422)
        self.assertEqual(self.call("unity_search_advance", job_id="stale").status_code, 422)
        for action, status in (("pause", "paused"), ("resume", "running"), ("cancel", "cancelled")):
            result = self.call("unity_search_control", job_id=first["job_id"], action=action)
            self.assertEqual(result.content["report"]["status"], status)
        self.assertEqual(self.call("unity_search_control", job_id=first["job_id"], action="resume").status_code, 422)

    def test_complete_saved_lookup_survives_new_failed_scan(self):
        state = search.new_scan("unity.example", "1228")
        state["tasks"] = state["tasks"][:1]
        search.save(self.directory.name, state)
        client = MagicMock()
        client.get.return_value = SimpleNamespace(status_code=200, json=lambda: {"@total": "0"})
        with patch.object(search.requests, "Session", return_value=client):
            self.assertEqual(self.call("unity_search_advance", job_id=state["job_id"]).status_code, 200)
        self.assertEqual(len(self.audit), 1)
        failed = search.new_scan("unity.example", "9999")
        failed["tasks"] = failed["tasks"][:1]
        search.save(self.directory.name, failed)
        client.get.return_value = SimpleNamespace(status_code=500)
        with patch.object(search.requests, "Session", return_value=client):
            self.call("unity_search_advance", job_id=failed["job_id"])
        self.request.url.path = "/unity-connection/search/saved"
        result = self.call("unity_search_saved")
        self.assertEqual(result.content["report"]["query"], "1228")

    def test_saved_available_without_password_and_report_write_failure(self):
        state = search.new_scan("unity.example", "1228")
        state["tasks"] = []
        search.save(self.directory.name, state)
        with patch.object(search, "save", side_effect=OSError("full")):
            result = self.call("unity_search_advance", job_id=state["job_id"])
        self.assertEqual(result.status_code, 502)
        self.assertEqual(search.load(self.directory.name, "unity.example")["status"], "running")
        self.scope["_resolve_unity_credentials"] = MagicMock(side_effect=RuntimeError("expired"))
        self.assertEqual(self.call("unity_search_saved").status_code, 200)

    def test_full_page_has_host_escaping_and_navigation(self):
        response = self.call("unity_connection_page")
        self.assertIn("Unity Connection Search", response.content)
        self.assertIn('href="/page2"', response.content)
        self.assertIn("Unity host: unity.example", response.content)
        self.assertNotIn("SECRET", response.content)

    def test_administrative_unity_tools_links(self):
        function = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == "menu_admin_page")
        html = max((node.value for node in ast.walk(function) if isinstance(node, ast.Constant) and isinstance(node.value, str) and "<html>" in node.value), key=len)
        self.assertIn('<a class="hero-link-card" href="/unity-connection">', html)
        self.assertIn("<strong>Unity Tools</strong>", html)
        self.assertIn("onclick=\"window.location.href='/unity-connection'\">Unity Tools</button>", html)


if __name__ == "__main__":
    unittest.main()
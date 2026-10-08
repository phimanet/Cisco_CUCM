import ast
import json
import tempfile
import threading
import unittest
from html import escape
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from toolkit import unity_user_extract as extract
from toolkit import unity_number_search as scanner


class UnityPersonExtractTests(unittest.TestCase):
    def setUp(self):
        self.user = {"ObjectId": "user-one", "Alias": "Example.User", "FirstName": "Example", "LastName": "User",
                     "DisplayName": "Example User", "EmailAddress": "example.user@example.com", "SmtpAddress": "example.user@example.com",
                     "DtmfAccessId": "8585236648", "CallHandlerURI": "/vmrest/handlers/callhandlers/handler-one"}
        self.client = MagicMock()
        self.client.__enter__.return_value = self.client

    def response(self, data):
        return SimpleNamespace(status_code=200, json=lambda: data)

    def test_extension_lookup_uses_server_filter_and_first_page_retry(self):
        self.client.get.side_effect = [self.response({"@total": "1"}), self.response({"@total": "1", "User": [self.user]})]
        with patch.object(extract.requests, "Session", return_value=self.client):
            result = extract.find_unity_person("unity.example", "admin", "SECRET", "extension", "8585236648")
        self.assertEqual(len(result["users"]), 1)
        self.assertEqual(result["requests"], 2)
        self.assertIn("(DtmfAccessId+is+8585236648)", self.client.get.call_args_list[0].args[0])
        self.assertEqual(self.client.get.call_args_list[1].kwargs["params"]["pageNumber"], 1)

    def test_name_lookup_and_query_validation(self):
        self.client.get.return_value = self.response({"@total": "1", "User": [self.user]})
        with patch.object(extract.requests, "Session", return_value=self.client):
            result = extract.find_unity_person("unity.example", "admin", "pass", "name", "Example User")
        self.assertEqual(result["users"][0]["name"], "Example User")
        with self.assertRaises(ValueError):
            extract.find_unity_person("unity.example", "admin", "pass", "name", "User) or (Alias is admin")

    def test_selected_user_extraction_does_not_inventory_all_users(self):
        self.client.get.return_value = self.response(self.user)
        with patch.object(extract.requests, "Session", return_value=self.client):
            state = extract.start_person_number_extract("unity.example", "admin", "pass", "user-one")
        resources = [task["resource"] for task in state["tasks"]]
        self.assertNotIn("/vmrest/users", resources)
        self.assertNotIn("/vmrest/handlers/callhandlers", resources)
        self.assertIn("/vmrest/handlers/callhandlers/handler-one/transferoptions", resources)
        scanner._schedule(state, "/vmrest/users/other-user", "Other user")
        self.assertNotIn("/vmrest/users/other-user", [task["resource"] for task in state["tasks"]])
        report = extract.person_number_report(state)
        self.assertTrue(any(row["value"] == "8585236648" for row in report["rows"]))
        self.assertFalse(report["complete"])
        self.client.post.assert_not_called()
        self.client.put.assert_not_called()
        self.client.delete.assert_not_called()

    def test_mismatched_user_identity_is_refused(self):
        self.client.get.return_value = self.response(dict(self.user, ObjectId="another-user"))
        with patch.object(extract.requests, "Session", return_value=self.client):
            with self.assertRaises(scanner.UnitySearchError):
                extract.start_person_number_extract("unity.example", "admin", "pass", "user-one")

    def test_email_lookup_checks_both_addresses_and_deduplicates_user(self):
        self.client.get.return_value = self.response({"@total": "1", "User": [self.user]})
        with patch.object(extract.requests, "Session", return_value=self.client):
            result = extract.find_unity_person("unity.example", "admin", "pass", "email", "example.user@example.com")
        self.assertEqual(len(result["users"]), 1)
        self.assertEqual(self.client.get.call_count, 2)
        self.assertIn("(SmtpAddress+is+", self.client.get.call_args_list[1].args[0])

    def test_empty_count_only_retry_is_not_user_not_found(self):
        self.client.get.side_effect = [self.response({"@total": "1"}), self.response({"@total": "0"})]
        with patch.object(extract.requests, "Session", return_value=self.client):
            with self.assertRaises(scanner.UnitySearchError):
                extract.find_unity_person("unity.example", "admin", "pass", "extension", "8585236648")

    def test_extract_includes_other_transfer_and_callback_numbers(self):
        self.client.get.return_value = self.response(self.user)
        with patch.object(extract.requests, "Session", return_value=self.client):
            state = extract.start_person_number_extract("unity.example", "admin", "pass", "user-one")
        owner = {"id": "handler-one", "name": "Example User primary handler", "type": "Primary User Call Handler"}
        scanner._ingest(state, {"Extension": "7001", "Enabled": "false", "Language": "7001"}, {"resource": "/vmrest/handlers/callhandlers/handler-one/transferoptions/Alternate", "label": "Transfer", "page": 0, "owner": owner})
        scanner._ingest(state, {"PhoneNumber": "8005550100", "CallbackNumber": "7002", "Password": "SECRET"}, {"resource": "/vmrest/users/user-one/notificationdevices/phonedevices/phone-one", "label": "Notification", "page": 0, "owner": owner})
        report = extract.person_number_report(state)
        self.assertEqual({row["value"] for row in report["rows"]}, {"8585236648", "7001", "7002", "8005550100"})
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertTrue(any("Enabled=false" in row["context"] for row in report["rows"]))

    def test_missing_primary_handler_is_visible_coverage_gap(self):
        user = {key: value for key, value in self.user.items() if key != "CallHandlerURI"}
        self.client.get.return_value = self.response(user)
        with patch.object(extract.requests, "Session", return_value=self.client):
            state = extract.start_person_number_extract("unity.example", "admin", "pass", "user-one")
        report = extract.person_number_report(state)
        self.assertTrue(any("Primary call handler" in item["detail"] for item in report["coverage_gaps"]))


class UnityPersonRoutesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8-sig"))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.session = {"username": "admin", "cucm_host": "lab"}
        def response(content=None, status_code=200, headers=None, **kwargs):
            return SimpleNamespace(content=content, body=json.dumps(content).encode(), status_code=status_code, headers=headers)
        self.scope = {"unity_number_search": scanner, "unity_user_extract": extract,
                      "UNITY_PERSON_NUMBER_EXTRACT_DIR": self.directory.name, "UNITY_NUMBER_SEARCH_LOCK": threading.Lock(),
                      "UNITY_REFERENCE_SEARCH_ENABLED": False, "json": json, "escape": escape, "Request": object,
                      "JSONResponse": response, "HTMLResponse": response, "Form": lambda value: value,
                      "_get_auth_session": lambda request: self.session, "_is_admin_user": lambda user: user == "admin",
                      "_get_unity_server_for_session": lambda request: "unity.example", "_resolve_unity_credentials": lambda *args: ("admin", "SECRET"),
                      "_get_environment_label": lambda host: ("LAB", "lab"), "_append_audit_event": lambda **kwargs: None}
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in {"MS_CALLING_PAGE_TEMPLATE", "UNITY_SEARCH_PAGE_BODY"} for target in node.targets):
                exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), self.scope)
            if isinstance(node, ast.FunctionDef) and (node.name.startswith("unity_person_") or node.name == "_unity_person_result" or node.name in {"_unity_search_access", "_unity_search_failure", "unity_connection_page"}):
                node.decorator_list = []
                exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), self.scope)
        self.request = SimpleNamespace(url=SimpleNamespace(path="/unity-connection/users/scan"))

    def call(self, name, **kwargs):
        return self.scope[name](self.request, **kwargs)

    def fixture_state(self):
        person = {"object_id": "user-one", "name": "Example User", "alias": "Example.User", "email": "example.user@example.com", "extension": "8585236648"}
        state = scanner.new_cache_scan("unity.example")
        state.update(purpose="mailbox_number_extract", person=person, mailbox_resources=["/vmrest/users/user-one"], tasks=[])
        owner = {"id": "user-one", "name": person["name"], "type": "User Mailbox"}
        state["fields"], _ = scanner.record_evidence({"Extension": person["extension"]}, owner, "/vmrest/users/user-one", number_entry_only=True)
        return state

    def test_routes_require_administrator(self):
        self.session["username"] = "other"
        for name, values in (("unity_person_find", {"search_by": "extension", "value": "8585236648"}),
                             ("unity_person_extract", {"object_id": "user-one"}), ("unity_person_saved", {}),
                             ("unity_person_advance", {"job_id": "one"}), ("unity_person_control", {"job_id": "one", "action": "pause"})):
            self.assertEqual(self.call(name, **values).status_code, 403)

    def test_legacy_number_reference_endpoints_are_retired(self):
        self.request.url.path = "/unity-connection/search/advance"
        with self.assertRaisesRegex(RuntimeError, "retired"):
            self.call("_unity_search_access")

    def test_page_replaces_number_reference_search(self):
        page = self.call("unity_connection_page").content
        self.assertIn("Unity Connection User Extract", page)
        self.assertIn("Find User", page)
        self.assertNotIn("Number Reference Search", page)
        self.assertNotIn("Load Cache", page)
        self.assertNotIn("SECRET", page)

    def test_saved_extract_and_stale_id_checks(self):
        state = self.fixture_state()
        state["status"] = "paused"
        scanner.save(self.directory.name, state)
        result = self.call("unity_person_saved")
        self.assertEqual(result.status_code, 200, result.content)
        self.assertEqual(result.content["report"]["field_count"], 1)
        self.assertEqual(self.call("unity_person_advance", job_id="wrong").status_code, 422)
        resumed = self.call("unity_person_control", job_id=state["job_id"], action="resume")
        self.assertEqual(resumed.content["report"]["status"], "running")
        restored = scanner.load(self.directory.name, "unity.example")
        self.assertEqual(restored["job_id"], state["job_id"])
        self.assertEqual(restored["person"], state["person"])

    def test_completed_extract_persists_and_failure_preserves_it(self):
        state = self.fixture_state()
        scanner.save(self.directory.name, state)
        complete = self.call("unity_person_advance", job_id=state["job_id"])
        self.assertTrue(complete.content["report"]["complete"])
        saved = scanner.load(self.directory.name, "unity.example", "report")
        failed = self.fixture_state()
        failed["coverage"].append({"resource": "/vmrest/users/user-one", "status": "Failed", "detail": "read denied"})
        scanner.save(self.directory.name, failed)
        result = self.call("unity_person_advance", job_id=failed["job_id"])
        self.assertFalse(result.content["report"]["complete"])
        self.assertEqual(scanner.load(self.directory.name, "unity.example", "report")["job_id"], saved["job_id"])


if __name__ == "__main__":
    unittest.main()
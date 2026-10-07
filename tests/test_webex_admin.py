import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from toolkit import webex_admin as webex


class WebexAdminTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"WEBEX_ACCESS_TOKEN": "SECRET", "WEBEX_ORG_ID": "org1"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.session = MagicMock()
        self.session.__enter__.return_value = self.session
        self.person = {"id": "person1", "orgId": "org1", "emails": ["test@example.com"],
                       "displayName": "Test Person", "licenses": ["license1"], "loginEnabled": True}

    def lookup(self, detail=None, catalog=None):
        responses = [({"items": [self.person]}, ""), (self.person if detail is None else detail, "")]
        if (self.person if detail is None else detail).get("licenses"):
            responses.append(({"items": [{"id": "license1", "name": "Webex Calling"}] if catalog is None else catalog}, ""))
        with patch.object(webex.requests, "Session", return_value=self.session), patch.object(webex, "_get", side_effect=responses) as read:
            report = webex.lookup_licenses("TEST@example.com")
        return report, read

    def test_license_lookup_and_only_three_reads(self):
        report, read = self.lookup()
        self.assertEqual(read.call_count, 3)
        self.assertEqual(report["licenses"][0]["name"], "Webex Calling")
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertEqual(read.call_args_list[0].args[2]["orgId"], "org1")
        self.session.post.assert_not_called()
        self.session.put.assert_not_called()
        self.session.delete.assert_not_called()

    def test_missing_license_field_is_not_no_licenses(self):
        detail = {key: value for key, value in self.person.items() if key != "licenses"}
        with self.assertRaisesRegex(webex.WebexError, "does not mean"):
            self.lookup(detail)

    def test_empty_license_list_is_explicit(self):
        report, read = self.lookup({**self.person, "licenses": []})
        self.assertEqual(report["license_count"], 0)
        self.assertEqual(read.call_count, 2)

    def test_unknown_license_name_does_not_hide_assigned_id(self):
        report, _ = self.lookup(catalog=[])
        self.assertEqual(report["licenses"][0]["id"], "license1")
        self.assertEqual(report["licenses"][0]["catalog_status"], "Not in returned catalog")
        self.assertTrue(report["warnings"])

    def test_wrong_organization_or_email_is_rejected(self):
        for detail in ({**self.person, "orgId": "other"}, {**self.person, "emails": ["other@example.com"]}):
            with self.subTest(detail=detail), self.assertRaises(webex.WebexError):
                self.lookup(detail)

    def test_catalog_pagination_and_host_isolation(self):
        next_url = "https://webexapis.com/v1/licenses?orgId=org1&cursor=next"
        with patch.object(webex, "_get", side_effect=[({"items": [{"id": "one"}]}, next_url), ({"items": [{"id": "two"}]}, "")]):
            self.assertEqual(len(webex._list(self.session, "licenses", "org1")), 2)
        for next_url in ("https://evil.example/licenses?orgId=org1", "https://webexapis.com/v1/licenses?orgId=other"):
            with patch.object(webex, "_get", return_value=({"items": []}, next_url)) as read, self.assertRaises(webex.WebexError):
                webex._list(self.session, "licenses", "org1")
            self.assertEqual(read.call_count, 1)

    def test_http_errors_do_not_return_provider_secret_payload(self):
        for code in (401, 403, 429, 500, 302):
            self.session.get.return_value = SimpleNamespace(status_code=code, text="SECRET", links={})
            with self.subTest(code=code), self.assertRaises(webex.WebexError) as error:
                webex._get(self.session, webex.API_BASE + "people")
            self.assertNotIn("SECRET", str(error.exception))
        self.assertFalse(self.session.get.call_args.kwargs["allow_redirects"])

    def test_atomic_saved_result_readback_failure_and_corruption(self):
        report, _ = self.lookup()
        with tempfile.TemporaryDirectory() as root:
            webex.save_report(root, report)
            self.assertEqual(webex.load_report(root, "org1")["person_id"], "person1")
            with self.assertRaises(FileNotFoundError):
                webex.load_report(root, "other")
            with patch.object(webex.os, "replace", side_effect=OSError("full")), self.assertRaises(OSError):
                webex.save_report(root, report)
            self.assertEqual(webex.load_report(root, "org1")["license_count"], 1)
            path = Path(webex._report_path(root, "org1"))
            path.write_text("{}")
            with self.assertRaises(webex.WebexError):
                webex.save_report(root, report)
            self.assertEqual(path.read_text(), "{}")

    def test_unconfigured_and_invalid_inputs_do_not_call_api(self):
        with patch.dict(os.environ, {"WEBEX_ACCESS_TOKEN": ""}), patch.object(webex.requests, "Session") as session:
            self.assertFalse(webex.configuration_status()["configured"])
            with self.assertRaises(webex.WebexError):
                webex.lookup_licenses("test@example.com")
            session.assert_not_called()
        with self.assertRaises(ValueError):
            webex.lookup_licenses("not an email")
        self.assertEqual(webex.WEBEX_LDAP_GROUP, "SSO_WebEX_AMNHealthcare")


if __name__ == "__main__":
    unittest.main()
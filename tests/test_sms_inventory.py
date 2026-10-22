import ast
import datetime
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from toolkit.sms_inventory import aerialink_numbers, twilio_sms_rows


def page(number=1, total=340, pages=4, following=None):
    size = min(100, max(0, total - (number - 1) * 100))
    return {"data": [{"codeGUID": str(index), "number": str(12140000000 + index),
                      "name": "Friendly <name>", "accountName": "Classic account", "connectionName": "Production"}
                     for index in range((number - 1) * 100, (number - 1) * 100 + size)],
            "paging": {"totalRecords": total, "totalPages": pages, "page": number,
                       "pageSize": 100, "pageCount": size,
                       "next": following if following is not None else (f"/v5/code?page={number + 1}&pageSize=100" if number < pages else None)}}


class SMSInventoryTests(unittest.TestCase):
    def read(self, payloads):
        get = Mock(side_effect=[SimpleNamespace(status_code=200, json=lambda value=value: value) for value in payloads])
        result = aerialink_numbers("https://example.test/v5", "/codes", "operator", "secret", get)
        return result, get

    def test_all_340_records_in_four_reads_and_sanitized_fields(self):
        rows, get = self.read([page(number) for number in range(1, 5)])
        self.assertEqual(len(rows), 340)
        self.assertEqual(get.call_count, 4)
        self.assertEqual(get.call_args_list[1].args[0], "https://example.test/v5/code?page=2&pageSize=100")
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in get.call_args_list))
        self.assertEqual(rows[0]["environment"], "AMIEClassic")
        self.assertEqual(rows[0]["friendly_name"], "Friendly <name>")
        self.assertNotIn("secret", str(rows))
        self.assertNotIn("emailAddress", str(rows))

    def test_foreign_host_and_path_refused_before_credentials_sent(self):
        for link in ("https://other.test/v5/code?page=2", "/v5/messages?page=2", "http://example.test/v5/code?page=2"):
            get = Mock(return_value=SimpleNamespace(status_code=200, json=lambda: page(following=link)))
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                aerialink_numbers("https://example.test/v5", "/codes", "operator", "secret", get)
            self.assertEqual(get.call_count, 1)

    def test_incomplete_changed_or_repeated_inventory_refused(self):
        for second in (page(1), page(2, total=339), {**page(2), "data": page(1)["data"]}):
            with self.assertRaises(ValueError):
                self.read([page(), second])
        last = page(4)
        last["paging"]["totalRecords"] = 341
        with self.assertRaises(ValueError):
            self.read([page(1), page(2), page(3), last])

    def test_empty_inventory_and_code_fallback(self):
        self.assertEqual(self.read([page(total=0, pages=0)])[0], [])
        payload = page(total=1, pages=1)
        payload["data"][0].pop("number")
        payload["data"][0]["code"] = "12345"
        self.assertEqual(self.read([payload])[0][0]["phone_number"], "12345")

    def test_invalid_json_metadata_and_http_errors(self):
        for payload in ({}, {**page(), "paging": {}}, {**page(), "data": None}):
            with self.assertRaises(ValueError):
                self.read([payload])
        get = Mock(return_value=SimpleNamespace(status_code=403))
        with self.assertRaisesRegex(ValueError, "HTTP 403"):
            aerialink_numbers("https://example.test/v5", "/codes", "operator", "secret", get)

    def test_twilio_sms_only_and_no_cross_account_deduplication(self):
        record = {"account_sid": "account1", "phone_number": "+12140000000", "account_name": "Greenlight QA",
                  "root_account_name": "Parent", "friendly_name": "Example", "capabilities": "VOICE, SMS"}
        rows = twilio_sms_rows({"rows": [record, record, {**record, "account_sid": "account2"}, {**record, "capabilities": "VOICE"}]})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["environment"], "Greenlight QA")


class SMSExtractRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        node = next(node for node in cls.tree.body if isinstance(node, ast.FunctionDef) and node.name == "sms_all_numbers_extract_route")
        node.decorator_list = []
        cls.code = compile(ast.Module(body=[node], type_ignores=[]), "<sms-route>", "exec")

    def setUp(self):
        self.twilio = Mock(return_value={"rows": [], "accounts": ["account"], "failures": []})
        self.aerialink = Mock(return_value=[{"provider": "Aerialink", "environment": "AMIEClassic", "account": "Classic", "phone_number": "12140000000"}])
        self.audit = Mock()
        self.scope = {"Request": object, "datetime": datetime,
                      "_get_auth_session": lambda request: {"username": "admin"},
                      "_is_admin_user": lambda username: username == "admin",
                      "_twilio_all_account_number_inventory": self.twilio,
                      "sms_inventory": SimpleNamespace(aerialink_numbers=self.aerialink, twilio_sms_rows=twilio_sms_rows),
                      "AERIALINK_V5_BASE_URL": "https://example.test/v5", "AERIALINK_ACCOUNT_CODE_LOOKUP_PATH": "/codes",
                      "AERIALINK_USERNAME": "operator", "AERIALINK_PASSWORD": "secret",
                      "_append_audit_event": self.audit,
                      "JSONResponse": lambda payload, status_code=200: SimpleNamespace(payload=payload, status_code=status_code)}
        exec(self.code, self.scope)

    def test_combined_route_and_no_messaging_service_reads(self):
        response = self.scope["sms_all_numbers_extract_route"](None)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.payload["count"], 1)
        self.assertEqual(response.payload["failures"], [])
        self.twilio.assert_called_once_with(include_messaging_services=False)
        self.audit.assert_called_once()
        self.assertNotIn("secret", str(response.payload))

    def test_authentication_blocks_both_provider_reads(self):
        self.scope["_get_auth_session"] = lambda request: {}
        response = self.scope["sms_all_numbers_extract_route"](None)
        self.assertEqual(response.status_code, 403)
        self.twilio.assert_not_called()
        self.aerialink.assert_not_called()

    def test_partial_provider_failure_is_visible_and_total_failure_is_not_empty_success(self):
        self.twilio.side_effect = RuntimeError("secret must not be exposed")
        response = self.scope["sms_all_numbers_extract_route"](None)
        self.assertEqual(response.payload["status"], "Partial")
        self.assertEqual(response.payload["count"], 1)
        self.assertTrue(response.payload["failures"])
        self.assertNotIn("secret", str(response.payload))
        self.aerialink.side_effect = ValueError("Aerialink inventory failed HTTP 403.")
        response = self.scope["sms_all_numbers_extract_route"](None)
        self.assertEqual(response.status_code, 502)
        self.assertFalse(response.payload["ok"])

    def test_page_has_isolated_menu_panel_and_full_filtered_export(self):
        node = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == "page3_twilio_items")
        html = next(value.value for value in ast.walk(node) if isinstance(value, ast.Constant) and isinstance(value.value, str) and "<title>SMS Item Menu" in value.value)
        self.assertIn('data-panel="sms-all-numbers"', html)
        self.assertIn('id="sms-all-extract"', html)
        self.assertIn('visible.slice(0,500)', html)
        self.assertIn('visible.forEach(function (row)', html)
        self.assertIn('all_sms_numbers.csv', html)


if __name__ == "__main__":
    unittest.main()
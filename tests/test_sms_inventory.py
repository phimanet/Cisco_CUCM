import ast
import datetime
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from toolkit.sms_inventory import InventoryCache, InventoryRefreshError
from toolkit.sms_inventory import annotate_review, normalized_number, failure_details
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


class SMSInventoryCacheTests(unittest.TestCase):
    def setUp(self):
        self.started = datetime.datetime(2026, 10, 27, 12, 0, tzinfo=datetime.timezone.utc)
        self.report = {"ok": True, "rows": [{"provider": "Twilio", "environment": "AMIEWeb", "account": "Parent", "phone_number": "+12145551000", "friendly_name": "Employee", "auth_token": "secret-must-not-be-saved"}], "failures": [], "fetched_at": self.started.isoformat(), "scope": "Twilio PN and Aerialink only"}

    def test_restart_reuses_cache_and_exact_eight_hour_boundary_refreshes(self):
        with tempfile.TemporaryDirectory() as root:
            extract = Mock(return_value=self.report)
            first = InventoryCache(root).get("account-scope", extract, at=self.started)
            second = InventoryCache(root).get("account-scope", extract, at=self.started + datetime.timedelta(hours=7, minutes=59))
            self.assertFalse(first["cache_hit"])
            self.assertTrue(second["cache_hit"])
            self.assertEqual(extract.call_count, 1)
            self.assertNotIn("secret-must-not-be-saved", InventoryCache(root).path.read_text())
            later = self.started + datetime.timedelta(hours=8)
            extract.return_value = {**self.report, "fetched_at": later.isoformat()}
            self.assertFalse(InventoryCache(root).get("account-scope", extract, at=later)["cache_hit"])
            self.assertEqual(extract.call_count, 2)

    def test_changed_accounts_cannot_reuse_previous_scope(self):
        with tempfile.TemporaryDirectory() as root:
            extract = Mock(return_value=self.report)
            cache = InventoryCache(root)
            cache.get("account-a", extract, at=self.started)
            cache.get("account-b", extract, at=self.started)
            self.assertEqual(extract.call_count, 2)

    def test_failed_or_partial_refresh_preserves_previous_successful_cache(self):
        with tempfile.TemporaryDirectory() as root:
            cache = InventoryCache(root)
            cache.get("scope", lambda: self.report, at=self.started)
            original = cache.path.read_bytes()
            later = self.started + datetime.timedelta(hours=9)
            with self.assertRaises(ValueError):
                cache.get("scope", lambda: {"ok": False}, at=later)
            partial = cache.get("scope", lambda: {**self.report, "fetched_at": later.isoformat(), "failures": ["Aerialink unavailable"]}, at=later)
            self.assertEqual(partial["status"], "Partial")
            self.assertEqual(cache.path.read_bytes(), original)

    def test_corrupt_future_and_failed_write_never_replace_previous_cache(self):
        with tempfile.TemporaryDirectory() as root:
            cache = InventoryCache(root)
            cache.get("scope", lambda: self.report, at=self.started)
            original = cache.path.read_bytes()
            with patch("toolkit.sms_inventory.os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    cache.get("other-scope", lambda: self.report, at=self.started)
            self.assertEqual(cache.path.read_bytes(), original)
            with self.assertRaises(ValueError):
                cache.get("scope", Mock(), at=self.started - datetime.timedelta(seconds=1))
            cache.path.write_text("invalid JSON")
            extract = Mock()
            with self.assertRaises(ValueError):
                cache.get("scope", extract, at=self.started)
            extract.assert_not_called()

    def test_number_matching_is_indexed_and_preserves_provider_account_boundaries(self):
        report = {**self.report, "status": "Complete within stated scope", "rows": [self.report["rows"][0], {**self.report["rows"][0], "environment": "Salesforce", "account": "Salesforce Parent"}]}
        snapshots = {str(index): {"extensions": [{"extension": "2145551000", "partition": "PT"}]} for index in range(200)}
        snapshots["missing"] = {"extensions": [{"extension": "2145559999", "partition": "PT"}]}
        result = annotate_review(snapshots, report)
        self.assertTrue(all(result[str(index)]["sms"] == "Yes" for index in range(200)))
        self.assertEqual(len(result["0"]["sms_matches"]), 2)
        self.assertEqual(result["missing"]["sms"], "No")
        self.assertEqual(normalized_number("+1 (214) 555-1000"), "2145551000")
        self.assertEqual(normalized_number("1000X"), "")

    def test_partial_or_failed_inventory_never_claims_unmatched_number_is_no(self):
        snapshots = {"found": {"extensions": [{"extension": "2145551000", "partition": "PT"}]}, "missing": {"extensions": [{"extension": "2145559999", "partition": "PT"}]}}
        result = annotate_review(snapshots, {**self.report, "status": "Partial", "failures": ["Provider failed"]})
        self.assertEqual(result["found"]["sms"], "Yes")
        self.assertEqual(result["missing"]["sms"], "Lookup Failed")
        self.assertEqual(annotate_review({"empty": {"extensions": []}}, {})["empty"]["sms"], "Not checked")

    def test_concurrent_reviews_share_one_extract(self):
        with tempfile.TemporaryDirectory() as root:
            calls, failures = [], []
            barrier = threading.Barrier(4)
            extract = Mock(return_value=self.report)
            def read():
                try:
                    barrier.wait(5)
                    calls.append(InventoryCache(root).get("scope", extract, at=self.started))
                except Exception as exc:
                    failures.append(exc)
            threads = [threading.Thread(target=read) for index in range(4)]
            for worker in threads:
                worker.start()
            for worker in threads:
                worker.join(5)
            self.assertEqual(failures, [])
            self.assertEqual(len(calls), 4)
            extract.assert_called_once()
            self.assertEqual(sum(not value["cache_hit"] for value in calls), 1)

    def test_missing_and_fresh_cache_report_distinct_extract_and_match_progress(self):
        with tempfile.TemporaryDirectory() as root:
            progress = Mock()
            cache = InventoryCache(root)
            cache.get("scope", lambda: self.report, at=self.started, progress=progress)
            self.assertIn("extracting a fresh", progress.call_args.args[0])
            progress.reset_mock()
            extract = Mock()
            cache.get("scope", extract, at=self.started, progress=progress)
            self.assertIn("matching extension digits locally", progress.call_args.args[0])
            extract.assert_not_called()

    def test_empty_success_is_cached_and_invalid_saved_rows_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            cache = InventoryCache(root)
            extract = Mock(return_value={**self.report, "rows": []})
            cache.get("scope", extract, at=self.started)
            cache.get("scope", extract, at=self.started)
            extract.assert_called_once()
            value = json.loads(cache.path.read_text())
            value["rows"] = [{"provider": "Twilio", "phone_number": "invalid"}]
            cache.path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                cache.get("scope", extract, at=self.started)
            extract.assert_called_once()


class SMSExtractRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        nodes = [node for node in cls.tree.body if isinstance(node, ast.FunctionDef) and node.name in {"sms_all_numbers_extract_route", "_extract_all_sms_numbers", "_sms_inventory_scope_key", "_cached_all_sms_numbers"}]
        for node in nodes:
            node.decorator_list = []
        cls.code = compile(ast.Module(body=nodes, type_ignores=[]), "<sms-route>", "exec")

    def setUp(self):
        self.twilio = Mock(return_value={"rows": [], "accounts": ["account"], "failures": []})
        self.aerialink = Mock(return_value=[{"provider": "Aerialink", "environment": "AMIEClassic", "account": "Classic", "phone_number": "12140000000"}])
        self.audit = Mock()
        self.scope = {"Request": object, "datetime": datetime, "hashlib": hashlib, "json": json,
                  "_twilio_inventory_configured_roots": Mock(return_value=([{"sid": "root-account", "name": "Parent", "auth_token": "provider-secret"}], [])),
                      "_get_auth_session": lambda request: {"username": "admin"},
                      "_is_admin_user": lambda username: username == "admin",
                      "_twilio_all_account_number_inventory": self.twilio,
                      "sms_inventory": SimpleNamespace(aerialink_numbers=self.aerialink, twilio_sms_rows=twilio_sms_rows, failure_details=failure_details, InventoryRefreshError=InventoryRefreshError),
                      "AERIALINK_V5_BASE_URL": "https://example.test/v5", "AERIALINK_ACCOUNT_CODE_LOOKUP_PATH": "/codes",
                      "AERIALINK_USERNAME": "operator", "AERIALINK_PASSWORD": "secret",
                      "_append_audit_event": self.audit,
                      "JSONResponse": lambda payload, status_code=200: SimpleNamespace(payload=payload, status_code=status_code)}
        exec(self.code, self.scope)
        self.real_cached = self.scope["_cached_all_sms_numbers"]
        def cached(force_refresh=False):
            result = self.scope["_extract_all_sms_numbers"]()
            if not result["ok"]:
                raise ValueError("Extract failed")
            return result
        self.scope["_cached_all_sms_numbers"] = Mock(side_effect=cached)

    def test_existing_manual_extract_seeds_cache_used_by_later_reviews(self):
        with tempfile.TemporaryDirectory() as root:
            self.scope["SMS_ALL_NUMBERS_CACHE"] = InventoryCache(root)
            self.scope["_cached_all_sms_numbers"] = self.real_cached
            response = self.scope["sms_all_numbers_extract_route"](None)
            self.assertEqual(response.status_code, 200)
            first = self.real_cached()
            second = self.real_cached()
            self.assertTrue(first["cache_hit"])
            self.assertTrue(second["cache_hit"])
            self.twilio.assert_called_once_with(force_refresh=True, include_messaging_services=False)
            self.aerialink.assert_called_once()
            self.assertNotIn("scope_key", response.payload)
            self.assertNotIn("provider-secret", InventoryCache(root).path.read_text())

    def test_scope_fingerprint_changes_with_configured_accounts_and_credentials(self):
        first = self.scope["_sms_inventory_scope_key"]()
        self.scope["_twilio_inventory_configured_roots"].return_value = ([{"sid": "different-account", "name": "Other", "auth_token": "different-secret"}], [])
        second = self.scope["_sms_inventory_scope_key"]()
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertNotIn("provider-secret", first)

    def test_combined_route_and_no_messaging_service_reads(self):
        response = self.scope["sms_all_numbers_extract_route"](None)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.payload["count"], 1)
        self.assertEqual(response.payload["failures"], [])
        self.twilio.assert_called_once_with(force_refresh=True, include_messaging_services=False)
        self.scope["_cached_all_sms_numbers"].assert_called_once_with(force_refresh=True)
        self.audit.assert_called_once()
        self.assertNotIn("secret", str(response.payload))

    def test_missing_cache_refreshes_provider_before_matching_then_reuses_inventory(self):
        with tempfile.TemporaryDirectory() as root:
            self.scope["SMS_ALL_NUMBERS_CACHE"] = InventoryCache(root)
            report = self.real_cached()
            self.assertFalse(report["cache_hit"])
            self.twilio.assert_called_once_with(force_refresh=True, include_messaging_services=False)
            result = annotate_review({"person": {"extensions": [{"extension": "2140000000", "partition": "PT"}]}}, report)
            self.assertEqual(result["person"]["sms"], "Yes")
            self.assertTrue(self.real_cached()["cache_hit"])
            self.assertEqual(self.twilio.call_count, 1)

    def test_authentication_blocks_both_provider_reads(self):
        self.scope["_get_auth_session"] = lambda request: {}
        response = self.scope["sms_all_numbers_extract_route"](None)
        self.assertEqual(response.status_code, 403)
        self.twilio.assert_not_called()
        self.aerialink.assert_not_called()

    def test_partial_transient_twilio_failure_is_retried_before_matching(self):
        self.twilio.side_effect = [{"rows": [], "accounts": ["account"], "failures": [{"account_name": "Parent", "error": "Lookup failed HTTP 503"}]}, {"rows": [], "accounts": ["account"], "failures": []}]
        report = self.scope["_extract_all_sms_numbers"]()
        self.assertEqual(report["status"], "Complete within stated scope")
        self.assertEqual(self.twilio.call_count, 2)
        self.assertTrue(all(call.kwargs["force_refresh"] for call in self.twilio.call_args_list))
        self.aerialink.assert_called_once()

    def test_aerialink_timeout_retry_does_not_repeat_successful_twilio_inventory(self):
        self.aerialink.side_effect = [ValueError("Aerialink inventory request failed; check connectivity"), [{"provider": "Aerialink", "environment": "AMIEClassic", "account": "Classic", "phone_number": "12140000000"}]]
        report = self.scope["_extract_all_sms_numbers"]()
        self.assertEqual(report["status"], "Complete within stated scope")
        self.assertEqual(self.aerialink.call_count, 2)
        self.twilio.assert_called_once()

    def test_auth_failure_is_not_retried_or_exposed_as_no(self):
        self.twilio.return_value = {"rows": [], "accounts": ["account"], "failures": [{"account_name": "Parent", "error": "Lookup failed HTTP 403 secret-token"}]}
        report = self.scope["_extract_all_sms_numbers"]()
        self.assertEqual(report["status"], "Partial")
        self.assertIn("Twilio / Parent: HTTP 403", report["failures"][0])
        self.assertNotIn("secret-token", str(report))
        self.twilio.assert_called_once()

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
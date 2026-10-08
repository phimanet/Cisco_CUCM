import ast
import json
import tempfile
import threading
import time
import unittest
from html import escape
from datetime import datetime, timedelta, timezone
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

    def test_count_only_first_page_retries_page_one_then_pages_normally(self):
        state = self.single_task()
        client = MagicMock()
        client.get.side_effect = [self.response({"@total": "2"}),
                                  self.response({"@total": "2", "Callhandler": [{"ObjectId": "one", "DtmfAccessId": "1228"}]}),
                                  self.response({"@total": "2", "Callhandler": [{"ObjectId": "two", "DtmfAccessId": "9999"}]})]
        search.advance_scan(state, "admin", "pass", client)
        self.assertEqual(state["tasks"][0]["page"], 1)
        self.assertEqual(state["coverage"], [])
        self.assertEqual(state["requests"], 1)
        search.advance_scan(state, "admin", "pass", client)
        search.advance_scan(state, "admin", "pass", client)
        self.assertEqual([call.kwargs["params"]["pageNumber"] for call in client.get.call_args_list], [0, 1, 2])
        self.assertEqual(state["coverage"][0]["status"], "Checked")
        self.assertEqual(state["records"], 2)
        self.assertEqual(len(search.find_matches(state)), 1)

    def test_count_only_retry_is_persisted_across_restart(self):
        state = self.single_task()
        client = MagicMock()
        client.get.side_effect = [self.response({"@total": "1"}),
                                  self.response({"@total": "1", "Callhandler": [{"ObjectId": "one", "DtmfAccessId": "1228"}]})]
        search.advance_scan(state, "admin", "pass", client)
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            restored = search.load(root, "unity.example")
            search.advance_scan(restored, "admin", "pass", client)
        self.assertEqual([call.kwargs["params"]["pageNumber"] for call in client.get.call_args_list], [0, 1])
        self.assertEqual(restored["status"], "completed")

    def test_count_only_retry_cannot_claim_empty_or_retry_forever(self):
        for second_page in ({"@total": "5"}, {"@total": "0"}, {"@total": "5", "Callhandler": []}):
            state = self.single_task()
            client = MagicMock()
            client.get.side_effect = [self.response({"@total": "5"}), self.response(second_page)]
            search.advance_scan(state, "admin", "pass", client)
            search.advance_scan(state, "admin", "pass", client)
            self.assertEqual(client.get.call_count, 2)
            self.assertFalse(search.scan_report(state)["cache_ready"])
            self.assertEqual(state["coverage"][0]["status"], "Failed")

    def test_count_only_later_page_remains_a_failure(self):
        state = self.single_task()
        client = MagicMock()
        client.get.side_effect = [self.response({"@total": "2", "Callhandler": [{"ObjectId": "one", "DtmfAccessId": "1228"}]}),
                                  self.response({"@total": "2"})]
        search.advance_scan(state, "admin", "pass", client)
        search.advance_scan(state, "admin", "pass", client)
        self.assertFalse(search.scan_report(state)["cache_ready"])
        self.assertEqual(state["coverage"][0]["status"], "Failed")

    def test_named_collections_with_metadata_and_wrappers(self):
        record = {"ObjectId": "one", "URI": "/vmrest/handlers/callhandlers/one", "DtmfAccessId": "1228"}
        for payload in ({"@total": "1", "Callhandler": [record], "links": [{"rel": "self"}], "metadata": {"count": 1}},
                        {"Callhandlers": {"@total": "1", "Callhandler": [record]}},
                        {"@total": "1", "Users": [record], "paging": {"offset": 0}}):
            rows, total = search._records(payload)
            self.assertEqual(rows, [record])
            self.assertEqual(total, 1)

    def test_parse_failure_diagnostics_expose_shape_not_values(self):
        with self.assertRaises(search.UnitySearchError) as context:
            search._records({"unknown1": {}, "unknown2": [], "Password": "SECRET"})
        self.assertIn("unknown1:dict", str(context.exception))
        self.assertNotIn("SECRET", str(context.exception))

    def test_optional_404_is_cacheable_but_stays_a_coverage_gap(self):
        state = search.new_cache_scan("unity.example")
        state["tasks"] = [{"resource": "/vmrest/configuration", "label": "System configuration", "page": 0, "owner": None}]
        client = MagicMock()
        client.get.return_value = self.response({}, 404)
        search.advance_scan(state, "admin", "pass", client)
        report = search.scan_report(state)
        self.assertTrue(report["cache_ready"])
        self.assertFalse(report["complete"])
        self.assertEqual(report["coverage_gaps"][0]["status"], "Unsupported")
        self.assertEqual(report["failures"], [])
        cache = search.completed_cache(state)
        self.assertTrue(search.cache_metadata(cache)["fresh"])
        self.assertTrue(search.search_cache(cache, "1228")["coverage_gaps"])

    def test_required_and_child_404_still_block_cache(self):
        for resource in ("/vmrest/handlers/callhandlers", "/vmrest/users", "/vmrest/handlers/callhandlers/one/greetings"):
            state = search.new_cache_scan("unity.example")
            state["tasks"] = [{"resource": resource, "label": "Required resource", "page": 0, "owner": None}]
            client = MagicMock()
            client.get.return_value = self.response({}, 404)
            search.advance_scan(state, "admin", "pass", client)
            self.assertFalse(search.scan_report(state)["cache_ready"])
            with self.assertRaises(search.UnitySearchError):
                search.completed_cache(state)

    def test_named_empty_collection_is_not_invalid_or_missing_records(self):
        self.assertEqual(search._records({"@total": "0", "User": None}), ([], 0))
        with self.assertRaises(search.UnitySearchError):
            search._records({"@total": "1", "User": None})

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

    def test_number_entry_focus_excludes_non_dialing_digits(self):
        owner = {"id": "one", "name": "One", "type": "Handler"}
        record = {"DtmfAccessId": "1228", "Extension": "1228", "Description": "old 1228", "Language": "1228", "TransferRings": 1228,
                  "TimeExpires": "2026-12-28", "PrependDigits": "1228", "AfterGreetingTargetHandlerObjectId": "other",
                  "Inputs": [{"TransferNumber": "1228"}]}
        fields, edges = search.record_evidence(record, owner, "/vmrest/handlers/callhandlers/one", number_entry_only=True)
        self.assertEqual({field["field"] for field in fields}, {"DtmfAccessId", "Extension", "PrependDigits", "Inputs[0].TransferNumber"})
        self.assertEqual(edges[0]["target"], "other")

    def test_number_entry_focus_keeps_routing_and_restriction_values(self):
        owner = {"id": "one", "name": "One", "type": "Rule"}
        for resource in ("/vmrest/routingrules/one/conditions/two", "/vmrest/restrictiontables/one/patterns/two"):
            fields, _ = search.record_evidence({"Value": "1228", "Pattern": "1228", "Priority": 1228}, owner, resource, number_entry_only=True)
            self.assertEqual({field["field"] for field in fields}, {"Value", "Pattern"})

    def test_number_entry_focus_migrates_without_losing_number_evidence(self):
        state = search.new_cache_scan("unity.example", "1228")
        state.pop("number_entry_focus")
        state["requests"] = 1020
        owner = {"id": "one", "name": "One", "type": "Handler"}
        fields, edges = search.record_evidence({"Extension": "1228", "Language": "1228", "TargetHandlerObjectId": "other"}, owner, "/vmrest/handlers/callhandlers/one")
        state.update(fields=fields, edges=edges)
        state["tasks"].append({"resource": "/vmrest/users/one/notificationdevices/smtpdevices/two", "label": "Notification", "owner": owner, "page": 0})
        search.focus_number_entry(state)
        self.assertEqual(state["requests"], 1020)
        self.assertEqual([item["field"] for item in state["fields"]], ["Extension"])
        self.assertEqual(state["edges"], edges)
        self.assertFalse(any("smtpdevices" in task["resource"] for task in state["tasks"]))
        self.assertTrue(state["excluded_links"])

    def test_number_entry_resources_keep_phone_pager_callback_and_mwi(self):
        for family in ("phonedevices", "pagerdevices", "htmldevices", "messagewaitingindicators", "alternateextensions"):
            self.assertTrue(search.number_entry_resource("/vmrest/users/one/" + family))
        self.assertFalse(search.number_entry_resource("/vmrest/users/one/notificationdevices/smtpdevices/two"))

    def test_user_collection_reuse_keeps_number_child_discovery(self):
        state = search.new_cache_scan("unity.example")
        root = {"resource": "/vmrest/users", "label": "Users", "page": 0, "owner": None}
        first = {"URI": "/vmrest/users/one", "ObjectId": "one", "Alias": "One", "DtmfAccessId": "1228"}
        search._ingest(state, first, root)
        detail = next(task for task in state["tasks"] if task["resource"] == first["URI"])
        search._ingest(state, first, detail)
        second = dict(first, URI="/vmrest/users/two", ObjectId="two", Alias="Two")
        search._ingest(state, second, root)
        resources = [task["resource"] for task in state["tasks"]]
        self.assertNotIn("/vmrest/users/two", resources)
        self.assertIn("/vmrest/users/two/alternateextensions", resources)
        self.assertIn("/vmrest/users/two/usernotificationdevices", resources)
        self.assertIn("/vmrest/users/two/messagewaitingindicators", resources)

    def test_focused_search_filters_legacy_cache_without_unity_reads(self):
        cache = self.cache_fixture()
        cache.pop("number_entry_focus", None)
        item = dict(cache["fields"][0], field="Language", value="1228")
        cache["fields"].append(item)
        with patch.object(search.requests, "Session") as client:
            report = search.search_cache(cache, "1228")
        client.assert_not_called()
        self.assertEqual(report["match_count"], 1)
        self.assertEqual(report["scope"], "Number-entry settings")
        self.assertIn("Descriptions, dates, language codes", report["limitations"])

    def test_focused_migration_persists_job_and_filtered_evidence(self):
        state = search.new_cache_scan("unity.example", "1228")
        state.pop("number_entry_focus")
        owner = {"id": "one", "name": "One", "type": "Handler"}
        state["fields"], _ = search.record_evidence({"Extension": "1228", "Language": "1228"}, owner, "/one")
        state.update(status="paused", requests=1020)
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            converted = search.enable_incremental(root, state)
            restored = search.load(root, state["host"])
            self.assertEqual(converted["job_id"], state["job_id"])
            self.assertEqual(restored["requests"], 1020)
            self.assertTrue(restored["number_entry_focus"])
            self.assertEqual([item["field"] for item in restored["fields"]], ["Extension"])

    def test_handler_collection_reuse_keeps_all_transfer_and_caller_settings(self):
        state = search.new_cache_scan("unity.example")
        root = {"resource": "/vmrest/handlers/callhandlers", "label": "Handlers", "page": 0, "owner": None}
        first = {"URI": "/vmrest/handlers/callhandlers/one", "ObjectId": "one", "DtmfAccessId": "1228", "IsPrimary": "false",
                 "TransferOptionsURI": "/vmrest/handlers/callhandlers/one/transferoptions", "MenuEntriesURI": "/vmrest/handlers/callhandlers/one/menuentries", "GreetingsURI": "/vmrest/handlers/callhandlers/one/greetings"}
        search._ingest(state, first, root)
        detail = next(task for task in state["tasks"] if task["resource"] == first["URI"])
        search._ingest(state, first, detail)
        second = {key: value.replace("/one", "/two") if isinstance(value, str) else value for key, value in first.items()}
        second["ObjectId"] = "two"
        search._ingest(state, second, root)
        resources = [task["resource"] for task in state["tasks"]]
        self.assertNotIn("/vmrest/handlers/callhandlers/two", resources)
        for child in ("transferoptions", "menuentries", "greetings"):
            self.assertIn("/vmrest/handlers/callhandlers/two/" + child, resources)

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

    def cache_fixture(self):
        state = search.new_cache_scan("unity.example")
        task = {"resource": "/vmrest/handlers/callhandlers", "owner": None, "label": "Handlers"}
        search._ingest(state, {"ObjectId": "one", "URI": "/vmrest/handlers/callhandlers/one", "DisplayName": "One",
                              "DtmfAccessId": "1228", "TransferNumber": "9999", "Password": "SECRET", "Pin": "1234"}, task)
        state.update(status="completed", tasks=[])
        return search.completed_cache(state)

    def test_cache_search_reuses_inventory_for_different_numbers(self):
        cache = self.cache_fixture()
        with patch.object(search.requests, "Session") as client:
            first = search.search_cache(cache, "1228", "exact")
            second = search.search_cache(cache, "9999", "exact")
        client.assert_not_called()
        self.assertEqual(first["rows"][0]["field"], "DtmfAccessId")
        self.assertEqual(second["rows"][0]["field"], "TransferNumber")
        self.assertNotIn("SECRET", json.dumps(cache))
        self.assertNotIn('"Pin"', json.dumps(cache))

    def test_cache_expires_at_eight_hours_and_survives_restart(self):
        cache = self.cache_fixture()
        beginning = datetime.fromisoformat(cache["cached_at"])
        self.assertTrue(search.cache_metadata(cache, beginning + timedelta(hours=8, seconds=-1))["fresh"])
        self.assertFalse(search.cache_metadata(cache, beginning + timedelta(hours=8))["fresh"])
        with self.assertRaises(search.UnitySearchError):
            search.search_cache(cache, "1228", now=beginning + timedelta(hours=8, seconds=1))
        with tempfile.TemporaryDirectory() as root:
            search.save(root, cache, "cache")
            self.assertEqual(search.search_cache(search.load(root, "unity.example", "cache"), "9999")["match_count"], 1)
            with self.assertRaises(FileNotFoundError):
                search.load(root, "other.example", "cache")

    def test_failed_cache_build_does_not_replace_previous_cache(self):
        cache = self.cache_fixture()
        with tempfile.TemporaryDirectory() as root:
            search.save(root, cache, "cache")
            state = search.new_cache_scan("unity.example")
            state.update(status="completed", tasks=[], coverage=[{"resource": "/vmrest/users", "status": "Failed", "detail": "HTTP 500"}])
            with self.assertRaises(search.UnitySearchError):
                search.completed_cache(state)
            self.assertEqual(search.load(root, "unity.example", "cache")["job_id"], cache["job_id"])

    def test_invalid_cache_timestamp_is_not_fresh(self):
        cache = self.cache_fixture()
        for timestamp in ("broken", "2026-10-08T00:00:00", (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()):
            cache["cached_at"] = timestamp
            with self.assertRaises(search.UnitySearchError):
                search.cache_metadata(cache)

    def test_windows_transient_file_lock_has_bounded_retry(self):
        cache = self.cache_fixture()
        replace = search.os.replace
        calls = []
        def locked_once(source, target):
            calls.append(target)
            if len(calls) == 1:
                raise PermissionError("locked")
            return replace(source, target)
        with tempfile.TemporaryDirectory() as root:
            with patch.object(search.os, "name", "nt"), patch.object(search.os, "replace", side_effect=locked_once), patch.object(search.time, "sleep") as delay:
                search.save(root, cache, "cache")
            self.assertEqual(len(calls), 2)
            delay.assert_called_once_with(0.05)
            self.assertEqual(search.load(root, "unity.example", "cache")["job_id"], cache["job_id"])

    def test_windows_permanent_file_lock_preserves_cache(self):
        cache = self.cache_fixture()
        with tempfile.TemporaryDirectory() as root:
            search.save(root, cache, "cache")
            updated = dict(cache, job_id="replacement")
            with patch.object(search.os, "name", "nt"), patch.object(search.os, "replace", side_effect=PermissionError("locked")) as replace, patch.object(search.time, "sleep"):
                with self.assertRaises(PermissionError):
                    search.save(root, updated, "cache")
            self.assertEqual(replace.call_count, 3)
            self.assertEqual(search.load(root, "unity.example", "cache")["job_id"], cache["job_id"])

    def test_incremental_migration_preserves_paused_legacy_state(self):
        state = search.new_cache_scan("unity.example", "1228")
        state.update(status="paused", requests=729, records=6000)
        state["tasks"][0].update(page=1, count_only_retry=True, count_only_total=3392, consumed=200)
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            original = Path(search._path(root, state["host"], "scan")).read_bytes()
            migrated = search.enable_incremental(root, state)
            self.assertEqual(migrated["job_id"], state["job_id"])
            self.assertEqual(migrated["status"], "paused")
            self.assertEqual(migrated["requests"], 729)
            self.assertEqual(migrated["tasks"], state["tasks"])
            self.assertEqual(Path(search._path(root, state["host"], "scan")).read_bytes(), original)
            migrated.update(status="running", requests=730)
            migrated["coverage"].append({"resource": "/checked", "status": "Checked", "detail": "one read"})
            migrated["tasks"].pop(0)
            search.save(root, migrated)
            restored = search.load(root, state["host"])
            self.assertEqual(restored["requests"], 730)
            self.assertEqual(restored["tasks"], migrated["tasks"])
            self.assertEqual(restored["coverage"], migrated["coverage"])

    def test_incremental_checkpoint_rejects_stale_updates(self):
        state = self.single_task()
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            current = search.enable_incremental(root, state)
            stale = search.load(root, state["host"])
            current["requests"] = 1
            search.save(root, current)
            with self.assertRaises(search.UnitySearchError):
                search.save(root, stale)
            self.assertEqual(search.load(root, state["host"])["requests"], 1)

    def test_incremental_pause_exports_latest_compatible_json(self):
        state = self.single_task()
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            current = search.enable_incremental(root, state)
            current.update(status="paused", requests=729)
            search.save(root, current)
            exported = search.load(root, state["host"], _json_only=True)
            self.assertEqual(exported["requests"], 729)
            self.assertEqual(exported["status"], "paused")
            self.assertEqual(exported["job_id"], state["job_id"])
            self.assertFalse(any(key.startswith("_") for key in exported))

    def test_corrupt_incremental_checkpoint_is_refused(self):
        state = self.single_task()
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            search.enable_incremental(root, state)
            Path(search._scan_db_path(root, state["host"])).write_bytes(b"corrupt")
            with self.assertRaises(search.UnitySearchError):
                search.load(root, state["host"])

    def test_parallel_reader_preserves_pages_and_uses_bounded_batch(self):
        state = search.new_cache_scan("unity.example")
        state["tasks"] = state["tasks"][:4]
        clients = []
        def factory():
            client = MagicMock()
            client.get.return_value = self.response({"@total": "0"})
            clients.append(client)
            return client
        checkpoints = []
        search.advance_parallel(state, "admin", "SECRET", lambda value: checkpoints.append(value["requests"]), factory)
        self.assertEqual(state["requests"], 4)
        self.assertEqual(state["status"], "completed")
        self.assertEqual(checkpoints, [1, 2, 3])
        self.assertLessEqual(len(clients), 2)
        self.assertEqual(sum(client.get.call_count for client in clients), 4)
        self.assertNotIn("SECRET", json.dumps(search.progress_report(state)))

    def test_progress_payload_is_small_for_large_paused_job(self):
        state = search.new_cache_scan("unity.example")
        state["status"] = "paused"
        state["tasks"] *= 2500
        state["coverage"] = [{"resource": "/checked/" + str(index), "status": "Checked", "detail": "read"} for index in range(20000)]
        report = search.progress_report(state)
        self.assertLess(len(json.dumps(report)), 3000)
        self.assertEqual(report["pending_resources"], 30000)
        self.assertEqual(report["checked_resources"], 20000)
        self.assertTrue(report["progress_only"])

    def test_complete_collection_reuse_requires_detail_match(self):
        state = search.new_cache_scan("unity.example")
        owner = {"id": "one", "name": "One", "type": "Handler"}
        root = "/vmrest/handlers/callhandlers/one/transferoptions"
        record = {key: "" for key in search.COLLECTION_REQUIRED_FIELDS["transferoptions"]}
        record.update(URI=root + "/Standard", CallHandlerObjectId="one", TransferOptionType="Standard", Extension="1228", Enabled="true")
        collection = {"resource": root, "label": "Handler", "page": 0, "owner": owner}
        search._ingest(state, record, collection)
        self.assertIn(root + "/Standard", [task["resource"] for task in state["tasks"]])
        detail = next(task for task in state["tasks"] if task["resource"] == root + "/Standard")
        search._ingest(state, record, detail)
        alternate = dict(record, URI=root + "/Alternate", TransferOptionType="Alternate")
        search._ingest(state, alternate, collection)
        self.assertNotIn(root + "/Alternate", [task["resource"] for task in state["tasks"]])
        self.assertTrue(any(item["resource"] == root + "/Alternate" and "collection record" in item["detail"] for item in state["coverage"]))

    def test_collection_detail_mismatch_keeps_individual_reads(self):
        state = search.new_cache_scan("unity.example")
        owner = {"id": "one", "name": "One", "type": "Handler"}
        root = "/vmrest/handlers/callhandlers/one/transferoptions"
        record = {key: "" for key in search.COLLECTION_REQUIRED_FIELDS["transferoptions"]}
        record.update(URI=root + "/Standard", Extension="1228")
        collection = {"resource": root, "label": "Handler", "page": 0, "owner": owner}
        search._ingest(state, record, collection)
        detail = next(task for task in state["tasks"] if task["resource"] == root + "/Standard")
        search._ingest(state, dict(record, ExtraNumber="9999"), detail)
        search._ingest(state, dict(record, URI=root + "/Alternate"), collection)
        self.assertIn(root + "/Alternate", [task["resource"] for task in state["tasks"]])

    def test_two_hundred_full_collection_records_reuse_verified_family(self):
        state = search.new_cache_scan("unity.example")
        base = {key: "" for key in search.COLLECTION_REQUIRED_FIELDS["transferoptions"]}
        for index in range(200):
            identity = str(index)
            owner = {"id": identity, "name": "Handler " + identity, "type": "Handler"}
            root = "/vmrest/handlers/callhandlers/" + identity + "/transferoptions"
            record = dict(base, URI=root + "/Standard", CallHandlerObjectId=identity, TransferOptionType="Standard", Extension="1228")
            collection = {"resource": root, "label": "Handler", "page": 0, "owner": owner}
            search._ingest(state, record, collection)
            if index == 0:
                detail = next(task for task in state["tasks"] if task["resource"] == record["URI"])
                search._ingest(state, record, detail)
        detail_tasks = [task for task in state["tasks"] if task["resource"].endswith("/transferoptions/Standard")]
        self.assertEqual(len(detail_tasks), 1)
        self.assertEqual(len(state["fields"]), 201)
        self.assertEqual(sum("collection record reused" in item["detail"] for item in state["coverage"]), 199)

    def test_parallel_reads_overlap_but_do_not_exceed_two(self):
        state = search.new_cache_scan("unity.example")
        state["tasks"] = state["tasks"][:4]
        lock = threading.Lock()
        active = [0]
        maximum = [0]
        starts = []
        def get(*args, **kwargs):
            with lock:
                active[0] += 1
                maximum[0] = max(maximum[0], active[0])
                starts.append(time.monotonic())
            threading.Event().wait(0.65)
            with lock:
                active[0] -= 1
            return self.response({"@total": "0"})
        def factory():
            client = MagicMock()
            client.get.side_effect = get
            return client
        search.advance_parallel(state, "admin", "pass", lambda value: None, factory)
        self.assertEqual(maximum[0], 2)
        self.assertTrue(all(second - first >= 0.45 for first, second in zip(starts, starts[1:])))

    def test_parallel_auth_failure_preserves_unfinished_tasks(self):
        state = search.new_cache_scan("unity.example")
        state["tasks"] = state["tasks"][:4]
        client = MagicMock()
        client.get.return_value = self.response({}, 403)
        checkpoints = []
        with self.assertRaises(search.UnitySearchError):
            search.advance_parallel(state, "admin", "pass", lambda value: checkpoints.append(value["status"]), lambda: client)
        self.assertEqual(state["status"], "paused")
        self.assertEqual(len(state["tasks"]), 4)
        self.assertEqual(checkpoints, ["paused"])

    def test_incremental_failure_rolls_back_checkpoint(self):
        state = self.single_task()
        with tempfile.TemporaryDirectory() as root:
            search.save(root, state)
            current = search.enable_incremental(root, state)
            connection = search.sqlite3.connect(search._scan_db_path(root, state["host"]))
            connection.execute("CREATE TRIGGER refuse_progress BEFORE UPDATE ON metadata BEGIN SELECT RAISE(ABORT,'blocked'); END")
            connection.commit()
            connection.close()
            current["requests"] = 123
            current["coverage"].append({"resource": "/new", "status": "Checked", "detail": "read"})
            with self.assertRaises(search.sqlite3.Error):
                search.save(root, current)
            restored = search.load(root, state["host"])
            self.assertEqual(restored["requests"], 0)
            self.assertEqual(restored["coverage"], [])


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
                      "UNITY_REFERENCE_SEARCH_ENABLED": True,
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
                                ("unity_search_control", {"job_id": "one", "action": "resume"}),
                                ("unity_search_cache_status", {}), ("unity_search_load_cache", {})):
            self.assertEqual(self.call(name, **arguments).status_code, 403)

    def test_duplicate_stale_pause_resume_cancel(self):
        first = self.call("unity_search_start", number="1228").content["report"]
        second = self.call("unity_search_start", number="1228").content["report"]
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(self.call("unity_search_start", number="9999").status_code, 422)
        self.assertEqual(self.call("unity_search_advance", job_id="stale").status_code, 422)
        for action, status in (("pause", "paused"), ("resume", "running"), ("cancel", "cancelled")):
            result = self.call("unity_search_control", job_id=first["job_id"], action=action)
            self.assertEqual(result.status_code, 200, result.content)
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
        self.assertIn("Unity Connection User Extract", response.content)
        self.assertIn('href="/page2"', response.content)
        self.assertIn("Unity host: unity.example", response.content)
        self.assertNotIn("SECRET", response.content)

    def test_administrative_unity_tools_links(self):
        function = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == "menu_admin_page")
        html = max((node.value for node in ast.walk(function) if isinstance(node, ast.Constant) and isinstance(node.value, str) and "<html>" in node.value), key=len)
        self.assertIn('<a class="hero-link-card" href="/unity-connection">', html)
        self.assertIn("<strong>Unity Tools</strong>", html)
        self.assertIn("onclick=\"window.location.href='/unity-connection'\">Unity Tools</button>", html)

    def cached_inventory(self):
        cache = UnityNumberSearchTests().cache_fixture()
        search.save(self.directory.name, cache, "cache")
        return cache

    def test_fresh_cache_search_makes_no_unity_reads(self):
        self.cached_inventory()
        self.scope["_resolve_unity_credentials"] = MagicMock(side_effect=RuntimeError("expired"))
        with patch.object(search.requests, "Session") as client:
            first = self.call("unity_search_start", number="1228", mode="exact")
            second = self.call("unity_search_start", number="9999", mode="exact")
        client.assert_not_called()
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(second.status_code, 200, second.content)
        self.assertEqual(first.content["report"]["source"], "cache")
        self.assertEqual(second.content["report"]["rows"][0]["field"], "TransferNumber")
        self.scope["_resolve_unity_credentials"].assert_not_called()
        self.assertEqual(len(self.audit), 2)
        self.assertTrue(all("source=cache" in event["target"] for event in self.audit))
        with self.assertRaises(FileNotFoundError):
            search.load(self.directory.name, "unity.example")

    def test_expired_cache_automatically_starts_refresh(self):
        cache = self.cached_inventory()
        cache["cached_at"] = (datetime.now(timezone.utc) - timedelta(hours=8, seconds=1)).isoformat()
        search.save(self.directory.name, cache, "cache")
        response = self.call("unity_search_start", number="9999")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.content["report"]["status"], "running")
        self.assertTrue(response.content["report"]["cache_build"])
        self.assertFalse(response.content["report"]["cache"]["fresh"])
        self.assertEqual(search.load(self.directory.name, "unity.example", "cache")["job_id"], cache["job_id"])

    def test_load_cache_forces_refresh_and_reuses_active_load(self):
        cache = self.cached_inventory()
        first = self.call("unity_search_load_cache").content["report"]
        second = self.call("unity_search_load_cache").content["report"]
        self.assertEqual(first["status"], "running")
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(first["query"], "")
        self.assertNotEqual(first["job_id"], cache["job_id"])
        attached = self.call("unity_search_start", number="1228")
        self.assertEqual(attached.content["report"]["source"], "cache")

    def test_missing_cache_load_finishes_pending_search_and_reuses_cache(self):
        result = self.call("unity_search_start", number="1228").content["report"]
        state = search.load(self.directory.name, "unity.example")
        inventory = UnityNumberSearchTests().cache_fixture()
        state.update(fields=inventory["fields"], edges=inventory["edges"], objects=inventory["objects"], tasks=[])
        search.save(self.directory.name, state)
        with patch.object(search.requests, "Session") as client:
            completed = self.call("unity_search_advance", job_id=result["job_id"])
            next_search = self.call("unity_search_start", number="9999")
        client.assert_not_called()
        self.assertEqual(completed.status_code, 200, completed.content)
        self.assertEqual(completed.content["report"]["match_count"], 1)
        self.assertTrue(search.load(self.directory.name, "unity.example", "cache")["collect_all_numbers"])
        self.assertEqual(next_search.content["report"]["source"], "cache")
        self.assertEqual(next_search.content["report"]["match_count"], 1)

    def test_failed_refresh_keeps_cache_and_last_search(self):
        cache = self.cached_inventory()
        prior = self.call("unity_search_start", number="1228").content["report"]
        load = self.call("unity_search_load_cache").content["report"]
        state = search.load(self.directory.name, "unity.example")
        state["tasks"] = state["tasks"][:1]
        search.save(self.directory.name, state)
        client = MagicMock()
        client.get.return_value = SimpleNamespace(status_code=500)
        with patch.object(search.requests, "Session", return_value=client):
            failed = self.call("unity_search_advance", job_id=load["job_id"])
        self.assertFalse(failed.content["report"]["complete"])
        self.assertEqual(search.load(self.directory.name, "unity.example", "cache")["job_id"], cache["job_id"])
        self.assertEqual(search.load(self.directory.name, "unity.example", "report")["job_id"], prior["job_id"])

    def test_cache_write_failure_does_not_finish_load(self):
        cache = self.cached_inventory()
        load = self.call("unity_search_load_cache").content["report"]
        state = search.load(self.directory.name, "unity.example")
        state["tasks"] = []
        search.save(self.directory.name, state)
        actual_save = search.save
        def failing_save(root, value, kind="scan"):
            if kind == "cache":
                raise OSError("full")
            return actual_save(root, value, kind)
        with patch.object(search, "save", side_effect=failing_save):
            response = self.call("unity_search_advance", job_id=load["job_id"])
        self.assertEqual(response.status_code, 502)
        self.assertEqual(search.load(self.directory.name, "unity.example")["status"], "running")
        self.assertEqual(search.load(self.directory.name, "unity.example", "cache")["job_id"], cache["job_id"])

    def test_corrupt_cache_is_not_replaced_or_used(self):
        self.cached_inventory()
        path = Path(search._path(self.directory.name, "unity.example", "cache"))
        path.write_text("broken", encoding="utf-8")
        self.assertEqual(self.call("unity_search_start", number="1228").status_code, 502)
        self.assertEqual(self.call("unity_search_load_cache").status_code, 502)
        self.assertEqual(path.read_text(encoding="utf-8"), "broken")

    def test_saved_report_recomputes_its_original_cache_age(self):
        self.cached_inventory()
        report = self.call("unity_search_start", number="1228").content["report"]
        report["cache"]["cached_at"] = (datetime.now(timezone.utc) - timedelta(hours=9)).isoformat()
        search.save(self.directory.name, report, "report")
        self.request.url.path = "/unity-connection/search/saved"
        response = self.call("unity_search_saved")
        self.assertFalse(response.content["report"]["cache"]["fresh"])
        self.assertGreater(response.content["report"]["cache"]["age_seconds"], 8 * 3600)

    def test_saved_scan_returns_cache_freshness_after_restart(self):
        self.cached_inventory()
        result = self.call("unity_search_load_cache").content["report"]
        response = self.call("unity_search_saved")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.content["report"]["job_id"], result["job_id"])
        self.assertTrue(response.content["report"]["cache"]["available"])
        self.assertTrue(response.content["report"]["cache"]["fresh"])

    def test_supported_inventory_is_saved_with_explicit_unsupported_gap(self):
        state = search.new_cache_scan("unity.example", "1228")
        inventory = UnityNumberSearchTests().cache_fixture()
        state.update(fields=inventory["fields"], edges=inventory["edges"], objects=inventory["objects"],
                     tasks=[], coverage=[{"resource": "/vmrest/configuration", "status": "Unsupported", "detail": "HTTP 404; not searched"}])
        search.save(self.directory.name, state)
        response = self.call("unity_search_advance", job_id=state["job_id"])
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.content["report"]["cache_ready"])
        self.assertFalse(response.content["report"]["complete"])
        self.assertEqual(search.load(self.directory.name, "unity.example", "cache")["coverage"][0]["status"], "Unsupported")
        result = self.call("unity_search_start", number="9999")
        self.assertEqual(result.content["report"]["source"], "cache")
        self.assertEqual(result.content["report"]["match_count"], 1)
        self.assertTrue(result.content["report"]["coverage_gaps"])

    def test_count_only_first_page_recovery_finishes_cache_load(self):
        initial = self.call("unity_search_start", number="1228").content["report"]
        state = search.load(self.directory.name, "unity.example")
        state["tasks"] = state["tasks"][:1]
        search.save(self.directory.name, state)
        client = MagicMock()
        client.get.side_effect = [SimpleNamespace(status_code=200, json=lambda: {"@total": "1"}),
                                  SimpleNamespace(status_code=200, json=lambda: {"@total": "1", "Callhandler": [{"ObjectId": "one", "DtmfAccessId": "1228", "TransferNumber": "9999"}]})]
        with patch.object(search.requests, "Session", return_value=client):
            first = self.call("unity_search_advance", job_id=initial["job_id"])
            self.assertEqual(first.content["report"]["status"], "running")
            self.assertEqual(search.load(self.directory.name, "unity.example")["tasks"][0]["page"], 1)
            second = self.call("unity_search_advance", job_id=initial["job_id"])
            cached = self.call("unity_search_start", number="9999")
        self.assertEqual(second.status_code, 200, second.content)
        self.assertTrue(second.content["report"]["cache"]["fresh"])
        self.assertEqual(second.content["report"]["match_count"], 1)
        self.assertEqual(cached.content["report"]["source"], "cache")
        self.assertEqual(cached.content["report"]["match_count"], 1)
        self.assertEqual(client.get.call_count, 2)

    def test_optimized_advance_returns_small_progress_and_keeps_coverage(self):
        state = search.new_cache_scan("unity.example", "1228")
        state["tasks"] = state["tasks"][:6]
        search.save(self.directory.name, state)
        client = MagicMock()
        client.get.return_value = SimpleNamespace(status_code=200, json=lambda: {"@total": "0"})
        with patch.object(search.requests, "Session", return_value=client):
            response = self.call("unity_search_advance", job_id=state["job_id"])
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.content["report"]["progress_only"])
        self.assertEqual(response.content["report"]["requests"], 4)
        self.assertEqual(response.content["report"]["coverage"], [])
        self.assertLess(len(response.body), 4000)
        restored = self.call("unity_search_saved").content["report"]
        self.assertEqual(len(restored["coverage"]), 4)
        self.assertEqual(restored["pending_resources"], 2)

    def test_legacy_paused_job_resumes_with_same_identity_and_progress(self):
        state = search.new_cache_scan("unity.example", "1228")
        state.update(status="paused", requests=729, records=7000)
        search.save(self.directory.name, state)
        response = self.call("unity_search_control", job_id=state["job_id"], action="resume")
        self.assertEqual(response.status_code, 200, response.content)
        restored = search.load(self.directory.name, "unity.example")
        self.assertEqual(restored["job_id"], state["job_id"])
        self.assertEqual(restored["requests"], 729)
        self.assertEqual(restored["records"], 7000)
        self.assertEqual(restored["tasks"], state["tasks"])
        self.assertTrue(restored["_incremental"])


if __name__ == "__main__":
    unittest.main()
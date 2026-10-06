import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

from toolkit import twilio_recent_logs as logs
from toolkit import twilio_all_recent_logs as all_logs


ACCOUNT = "AC" + "a" * 32
OTHER_ACCOUNT = "AC" + "b" * 32
NUMBER = "+12142105932"


def inventory(number=NUMBER, sms=True):
    return {"account_sid": ACCOUNT, "phone_number": number, "capabilities": {"sms": sms}}


def message(direction="outbound-api", **fields):
    return {"account_sid": ACCOUNT, "from": NUMBER, "direction": direction,
            "date_sent": "Tue, 06 Oct 2026 16:30:00 +0000", "body": "PRIVATE MESSAGE BODY",
            "to": "+15551234567", **fields}


def response(messages=None, next_uri=None, status=200, **payload):
    return SimpleNamespace(status_code=status, headers={"Retry-After": "2"},
                           json=lambda: {"messages": messages or [], "next_page_uri": next_uri, **payload})


class InventoryTests(unittest.TestCase):
    def test_deduplication_and_sms_only(self):
        numbers, excluded = logs.sms_numbers([inventory(), inventory(), inventory("+12142105933", False)], ACCOUNT)
        self.assertEqual(numbers, [NUMBER])
        self.assertEqual(excluded, 1)

    def test_account_capability_and_number_validation(self):
        for item in ({**inventory(), "account_sid": OTHER_ACCOUNT}, {**inventory(), "capabilities": {}}, inventory("invalid"), None):
            with self.subTest(item=item), self.assertRaises(ValueError):
                logs.sms_numbers([item], ACCOUNT)


class MessageTests(unittest.TestCase):
    def read(self, reply, **kwargs):
        with patch.object(logs.requests, "get", return_value=reply) as get:
            result = logs.read_latest_outbound_page(ACCOUNT, ACCOUNT, "AUTH SECRET", NUMBER, **kwargs)
        return result, get

    def test_latest_outbound_timestamp_only_and_call_count(self):
        for direction in logs.OUTBOUND_DIRECTIONS:
            result, get = self.read(response([message(direction)]))
            self.assertEqual(result["latest_outbound_at"], "2026-10-06T16:30:00+00:00")
            self.assertEqual(result["timestamp_source"], "date_sent")
            self.assertEqual(get.call_count, 1)
            self.assertEqual(get.call_args.kwargs["params"], {"From": NUMBER, "PageSize": 1})
            self.assertFalse(get.call_args.kwargs["allow_redirects"])
            self.assertNotIn("PRIVATE MESSAGE BODY", json.dumps(result))
            self.assertNotIn("AUTH SECRET", json.dumps(result))
            self.assertNotIn("to", result)

    def test_creation_time_fallback_is_explicit(self):
        result, _ = self.read(response([message(date_sent=None, date_created="2026-10-06T17:00:00Z")]))
        self.assertEqual(result["timestamp_source"], "date_created")
        self.assertEqual(result["latest_outbound_at"], "2026-10-06T17:00:00+00:00")

    def test_inbound_is_skipped_with_scoped_pagination(self):
        uri = f"/2010-04-01/Accounts/{ACCOUNT}/Messages.json?From=%2B12142105932&PageSize=1&Page=1"
        result, _ = self.read(response([message("inbound")], uri))
        self.assertEqual(result["status"], "Continue")
        self.assertEqual(result["pages_read"], 1)
        found, get = self.read(response([message()]), next_uri=uri, pages_read=1)
        self.assertEqual(found["status"], "Found")
        self.assertIsNone(get.call_args.kwargs["params"])

    def test_missing_history_is_not_a_failed_lookup(self):
        result, _ = self.read(response())
        self.assertEqual(result["status"], "No outbound log available")
        failed, _ = self.read(response(status=400))
        self.assertEqual(failed["status"], "Lookup Failed")

    def test_invalid_payload_identity_and_timestamp_fail_closed(self):
        cases = [
            response([message(account_sid=OTHER_ACCOUNT)]), response([message(**{"from": "+12142105933"})]),
            response([message(direction="unknown")]), response([message(date_sent="broken")]),
            response([message(date_sent="2026-10-06T16:30:00")]), response(messages="invalid"),
            response([message("inbound")], "https://evil.example/steal"),
        ]
        for reply in cases:
            result, _ = self.read(reply)
            self.assertEqual(result["status"], "Lookup Failed")

    def test_cross_account_page_links_are_never_requested(self):
        uris = [f"/2010-04-01/Accounts/{OTHER_ACCOUNT}/Messages.json?From=%2B12142105932",
                "https://evil.example/messages?From=%2B12142105932",
                f"/2010-04-01/Accounts/{ACCOUNT}/Messages.json?From=%2B12142105933"]
        for uri in uris:
            with patch.object(logs.requests, "get") as get, self.assertRaises(ValueError):
                logs.read_latest_outbound_page(ACCOUNT, ACCOUNT, "SECRET", NUMBER, next_uri=uri)
            get.assert_not_called()

    def test_auth_throttle_and_transport_errors_are_distinct(self):
        denied, _ = self.read(response(status=401))
        retry, _ = self.read(response(status=429))
        self.assertEqual(denied["status"], "Account Error")
        self.assertEqual(retry["status"], "Retry")
        with patch.object(logs.requests, "get", side_effect=requests.ConnectionError("SECRET CONTENT")):
            result = logs.read_latest_outbound_page(ACCOUNT, ACCOUNT, "SECRET", NUMBER)
        self.assertEqual(result["status"], "Retry")
        self.assertNotIn("SECRET", json.dumps(result))
        limited = logs.read_latest_outbound_page(ACCOUNT, ACCOUNT, "SECRET", NUMBER, pages_read=logs.MAX_MESSAGE_PAGES)
        self.assertEqual(limited["status"], "Lookup Failed")


class StateTests(unittest.TestCase):
    def test_friendly_names_are_kept_from_inventory_without_more_reads(self):
        state = logs.create_job([{**inventory(" " + NUMBER + " "), "friendly_name": "Chris Smith"}, inventory("+12142105933"), {"account_sid": ACCOUNT, "capabilities": {"sms": False}}], ACCOUNT, "AMIEWeb")
        self.assertEqual(state["rows"][0]["friendly_name"], "Chris Smith")
        self.assertEqual(state["rows"][1]["friendly_name"], "")
        with patch.object(logs, "read_latest_outbound_page", return_value={"status": "Found", "latest_outbound_at": "2026-10-06T16:30:00+00:00", "timestamp_source": "date_sent"}) as read:
            logs.advance_job(state, ACCOUNT, ACCOUNT, "SECRET")
        self.assertEqual(read.call_count, 1)
        self.assertEqual(logs.public_state(state)["rows"][0]["friendly_name"], "Chris Smith")

    def test_two_hundred_numbers_use_one_latest_read_each(self):
        items = [inventory("+1555" + str(1000000 + index)) for index in range(200)]
        state = logs.create_job(items, ACCOUNT, "AMIEWeb")
        with patch.object(logs, "read_latest_outbound_page", return_value={"status": "Found", "latest_outbound_at": "2026-10-06T16:30:00+00:00", "timestamp_source": "date_sent"}) as read:
            for _ in range(200):
                logs.advance_job(state, ACCOUNT, ACCOUNT, "SECRET")
        self.assertEqual(read.call_count, 200)
        self.assertEqual(len({call.args[3] for call in read.call_args_list}), 200)
        self.assertEqual(state["status"], "completed")
        self.assertEqual(logs.public_state(state)["found"], 200)

    def test_restart_resume_and_atomic_failed_write(self):
        state = logs.create_job([inventory(), inventory("+12142105933")], ACCOUNT, "AMIEWeb")
        with tempfile.TemporaryDirectory() as root:
            with patch.object(logs, "read_latest_outbound_page", return_value={"status": "Found", "latest_outbound_at": "2026-10-06T16:30:00+00:00", "timestamp_source": "date_sent"}):
                logs.advance_job(state, ACCOUNT, ACCOUNT, "SECRET")
            logs.save_state(root, state)
            restored = logs.load_state(root, ACCOUNT)
            self.assertEqual(restored["cursor"], 1)
            with patch.object(logs, "read_latest_outbound_page", return_value={"status": "No outbound log available"}) as read:
                logs.advance_job(restored, ACCOUNT, ACCOUNT, "SECRET")
            self.assertEqual(read.call_args.args[3], "+12142105933")
            self.assertEqual(restored["status"], "completed")
            logs.save_state(root, restored, "report")
            before = Path(logs.state_path(root, ACCOUNT, "report")).read_text()
            with patch.object(logs.os, "replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
                logs.save_state(root, restored, "report")
            self.assertEqual(before, Path(logs.state_path(root, ACCOUNT, "report")).read_text())
            self.assertNotIn("SECRET", before)
            self.assertEqual(logs.public_state(restored)["no_history"], 1)

    def test_retry_progress_is_bounded_and_respects_delay(self):
        state = logs.create_job([inventory()], ACCOUNT, "AMIEWeb")
        with patch.object(logs.time, "time", return_value=100), patch.object(logs, "read_latest_outbound_page", return_value={"status": "Retry", "retry_after": 2}) as read:
            logs.advance_job(state, ACCOUNT, ACCOUNT, "SECRET")
            logs.advance_job(state, ACCOUNT, ACCOUNT, "SECRET")
            self.assertEqual(read.call_count, 1)
        self.assertEqual(state["cursor"], 0)
        for now in (103, 106, 109):
            with patch.object(logs.time, "time", return_value=now), patch.object(logs, "read_latest_outbound_page", return_value={"status": "Retry", "retry_after": 2}):
                logs.advance_job(state, ACCOUNT, ACCOUNT, "SECRET")
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["rows"][0]["status"], "Lookup Failed")

    def test_account_errors_stop_without_false_no_history(self):
        state = logs.create_job([inventory()], ACCOUNT, "AMIEWeb")
        with patch.object(logs, "read_latest_outbound_page", return_value={"status": "Account Error", "error": "Denied"}):
            logs.advance_job(state, ACCOUNT, ACCOUNT, "SECRET")
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["rows"][0]["status"], "Pending")
        self.assertEqual(logs.public_state(state)["no_history"], 0)
        with self.assertRaises(ValueError):
            logs.advance_job(state, OTHER_ACCOUNT, OTHER_ACCOUNT, "SECRET")

    def test_corrupt_state_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            Path(logs.state_path(root, ACCOUNT, "job")).write_text('{"account_sid":"wrong"}')
            with self.assertRaises(ValueError):
                logs.load_state(root, ACCOUNT)


class AllAccountQueueTests(unittest.TestCase):
    def roots(self):
        return [{"sid": ACCOUNT, "name": "AMIEWeb", "auth_token": "SECRET AMIE"},
                {"sid": OTHER_ACCOUNT, "name": "PA Org Prod", "auth_token": "SECRET PA"}]

    def row(self, index, account=ACCOUNT, root=ACCOUNT):
        return {"account_sid": account, "account_name": "AMIEWeb" if account == ACCOUNT else "PA Org Prod",
                "root_account_sid": root, "root_account_name": "Root",
                "phone_number": "+1555" + str(1000000 + index), "friendly_name": "Person " + str(index), "capabilities": "SMS"}

    def inventory(self, rows, failures=None):
        accounts = [{"sid": sid, "friendly_name": "Account", "root_account_sid": sid} for sid in {row["account_sid"] for row in rows}]
        return {"rows": rows, "accounts": accounts, "failures": failures or []}

    def test_thirteen_hundred_numbers_restart_resume_and_full_report(self):
        state = all_logs.create_job(self.roots(), "operator")
        self.assertEqual(state["status"], "queued")
        self.assertFalse(state["inventory_ready"])
        rows = [self.row(index, ACCOUNT if index < 650 else OTHER_ACCOUNT, ACCOUNT if index < 650 else OTHER_ACCOUNT) for index in range(1300)]
        all_logs.initialize_inventory(state, self.inventory(rows))
        result = {"status": "Found", "latest_outbound_at": "2026-10-06T16:30:00+00:00", "timestamp_source": "date_sent"}
        with tempfile.TemporaryDirectory() as directory, patch.object(logs, "read_latest_outbound_page", return_value=result) as read:
            for _ in range(650):
                all_logs.advance_job(state, self.roots())
            all_logs.save_state(directory, state)
            restored = all_logs.load_state(directory)
            for _ in range(650):
                all_logs.advance_job(restored, self.roots())
            self.assertEqual(read.call_count, 1300)
            self.assertEqual(len({(call.args[0], call.args[3]) for call in read.call_args_list}), 1300)
            self.assertEqual(restored["status"], "completed")
            all_logs.save_state(directory, restored, "report")
            self.assertEqual(len(all_logs.load_state(directory, "report")["rows"]), 1300)
            self.assertNotIn("SECRET", json.dumps(restored))
            self.assertEqual(all_logs.public_state(restored, include_rows=False)["found"], 1300)
            self.assertNotIn("rows", all_logs.public_state(restored, include_rows=False))

    def test_same_number_deduplicated_per_account_not_across_accounts(self):
        state = all_logs.create_job(self.roots(), "operator")
        rows = [self.row(1), self.row(1), self.row(1, OTHER_ACCOUNT, OTHER_ACCOUNT)]
        all_logs.initialize_inventory(state, self.inventory(rows))
        self.assertEqual(len(state["rows"]), 2)

    def test_explicit_child_credentials_override_parent_auth(self):
        state = all_logs.create_job(self.roots(), "operator")
        all_logs.initialize_inventory(state, self.inventory([self.row(1, OTHER_ACCOUNT, ACCOUNT)]))
        with patch.object(logs, "read_latest_outbound_page", return_value={"status": "No outbound log available"}) as read:
            all_logs.advance_job(state, self.roots())
        self.assertEqual(read.call_args.args[:3], (OTHER_ACCOUNT, OTHER_ACCOUNT, "SECRET PA"))

    def test_child_only_account_uses_parent_auth_without_switching_inventory(self):
        state = all_logs.create_job([self.roots()[0]], "operator")
        all_logs.initialize_inventory(state, self.inventory([self.row(1, OTHER_ACCOUNT, ACCOUNT)]))
        with patch.object(logs, "read_latest_outbound_page", return_value={"status": "No outbound log available"}) as read:
            all_logs.advance_job(state, [self.roots()[0]])
        self.assertEqual(read.call_args.args[:3], (OTHER_ACCOUNT, ACCOUNT, "SECRET AMIE"))

    def test_account_failure_skips_its_remaining_numbers_and_continues_others(self):
        state = all_logs.create_job(self.roots(), "operator")
        all_logs.initialize_inventory(state, self.inventory([self.row(1), self.row(2), self.row(3, OTHER_ACCOUNT, OTHER_ACCOUNT)]))
        with patch.object(logs, "read_latest_outbound_page", side_effect=[{"status": "Account Error", "error": "HTTP 403"}, {"status": "Found", "latest_outbound_at": "2026-10-06T16:30:00+00:00", "timestamp_source": "date_sent"}]) as read:
            all_logs.advance_job(state, self.roots())
            self.assertEqual(state["cursor"], 2)
            all_logs.advance_job(state, self.roots())
        self.assertEqual(read.call_count, 2)
        self.assertEqual(state["status"], "completed")
        self.assertEqual(all_logs.public_state(state)["failed"], 2)
        self.assertEqual(all_logs.public_state(state)["found"], 1)
        self.assertEqual(all_logs.public_state(state)["no_history"], 0)

    def test_inventory_failures_and_non_sms_exclusions_are_visible(self):
        state = all_logs.create_job(self.roots(), "operator")
        non_sms = {**self.row(2), "capabilities": "VOICE"}
        failures = [{"account_sid": OTHER_ACCOUNT, "account_name": "PA Org Prod", "error": "HTTP 403 SECRET SHOULD NEVER BE SAVED"}]
        all_logs.initialize_inventory(state, self.inventory([self.row(1), non_sms], failures))
        self.assertEqual(state["excluded_non_sms"], 1)
        self.assertEqual(len(state["inventory_failures"]), 1)
        self.assertIn("HTTP 403", state["inventory_failures"][0]["error"])
        self.assertNotIn("SECRET", json.dumps(state))

    def test_out_of_scope_account_and_root_change_fail_closed(self):
        state = all_logs.create_job(self.roots(), "operator")
        with self.assertRaises(ValueError):
            all_logs.initialize_inventory(state, self.inventory([self.row(1, ACCOUNT, "AC" + "c" * 32)]))
        all_logs.initialize_inventory(state, self.inventory([self.row(1)]))
        with patch.object(logs, "read_latest_outbound_page") as read, self.assertRaises(ValueError):
            all_logs.advance_job(state, [self.roots()[0]])
        read.assert_not_called()

    def test_failed_atomic_write_retains_prior_report_and_corrupt_state_is_refused(self):
        state = all_logs.create_job(self.roots(), "operator")
        all_logs.initialize_inventory(state, self.inventory([]))
        with tempfile.TemporaryDirectory() as directory:
            all_logs.save_state(directory, state, "report")
            before = Path(directory, "report.json").read_text()
            with patch.object(all_logs.os, "replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
                all_logs.save_state(directory, state, "report")
            self.assertEqual(before, Path(directory, "report.json").read_text())
            Path(directory, "job.json").write_text("{}")
            with self.assertRaises(ValueError):
                all_logs.load_state(directory)

    def test_all_inventory_failed_is_not_successful_empty_report(self):
        state = all_logs.create_job(self.roots(), "operator")
        all_logs.initialize_inventory(state, self.inventory([], [{"account_sid": ACCOUNT, "account_name": "Root", "error": "HTTP 403"}]))
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["error"])

    def test_all_message_lookups_failed_is_not_a_completed_report(self):
        state = all_logs.create_job(self.roots(), "operator")
        all_logs.initialize_inventory(state, self.inventory([self.row(1), self.row(2, OTHER_ACCOUNT, OTHER_ACCOUNT)]))
        with patch.object(logs, "read_latest_outbound_page", return_value={"status": "Account Error", "error": "HTTP 403"}):
            all_logs.advance_job(state, self.roots())
            all_logs.advance_job(state, self.roots())
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["cursor"], 2)
        self.assertEqual(all_logs.public_state(state)["failed"], 2)
        self.assertIn("previous completed report is retained", state["error"])


if __name__ == "__main__":
    unittest.main()
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import requests

from toolkit import twilio_recent_logs as logs


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


if __name__ == "__main__":
    unittest.main()
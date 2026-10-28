import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from toolkit import sms_only_bulk


class SmsBulkParsingTests(unittest.TestCase):
    def test_parses_headered_csv_and_rejects_bad_and_duplicate_rows(self):
        rows = sms_only_bulk.parse_sms_bulk_rows(
            "Email,Number\nalice.smith@example.com,9451234567\n"
            "alice.smith@example.com,9451234568\nbob.jones@example.com,12345\n"
        )

        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["status"], "pending")
        self.assertEqual(rows[1]["status"], "duplicate")
        self.assertEqual(rows[2]["status"], "invalid")
        self.assertIn("exactly 10 digits", rows[2]["detail"])

    def test_parses_tab_delimited_input(self):
        rows = sms_only_bulk.parse_sms_bulk_rows("alice.smith@example.com\t9451234567")
        self.assertEqual(rows[0]["email"], "alice.smith@example.com")
        self.assertEqual(rows[0]["number"], "9451234567")


class SmsBulkPrecheckTests(unittest.TestCase):
    def test_precheck_handles_more_than_forty_rows_with_batched_reads(self):
        raw_rows = "\n".join(
            f"person{index}@example.com,945{index:07d}"
            for index in range(1, 46)
        )
        rows = sms_only_bulk.parse_sms_bulk_rows(raw_rows)
        queries = []

        def read_sql(host, username, password, sql):
            queries.append(sql)
            if "FROM enduser" in sql:
                return [
                    {"userid": f"person{index}", "first_name": f"Person{index}", "last_name": "Test", "email": f"person{index}@example.com"}
                    for index in range(1, 46)
                ]
            return [
                {"pattern": f"945{index:07d}", "route_partition": "ENT_DEVICE_PT", "pattern_usage": "2", "iscallable": "f", "device_count": "0"}
                for index in range(1, 46)
            ]

        with patch.object(sms_only_bulk.sms_only_user, "list_sms_only_patterns", return_value=[]):
            checked = sms_only_bulk.precheck_sms_bulk_rows(rows, "cucm", "operator", "secret", read_sql)

        self.assertEqual(len(checked), 45)
        self.assertTrue(all(row["status"] == "available" for row in checked.values()))
        self.assertEqual(len(queries), 2)

    def test_precheck_batches_email_and_number_and_marks_available(self):
        rows = sms_only_bulk.parse_sms_bulk_rows("alice.smith@example.com,9451234567")
        queries = []

        def read_sql(host, username, password, sql):
            queries.append(sql)
            if "FROM enduser" in sql:
                return [{"userid": "alice.smith", "first_name": "Alice", "last_name": "Smith", "email": "alice.smith@example.com"}]
            return [{"pattern": "9451234567", "route_partition": "ENT_DEVICE_PT", "pattern_usage": "2", "iscallable": "f", "device_count": "0"}]

        with patch.object(sms_only_bulk.sms_only_user, "list_sms_only_patterns", return_value=[]):
            checked = sms_only_bulk.precheck_sms_bulk_rows(rows, "cucm", "operator", "secret", read_sql)

        result = checked["1"]
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["userid"], "alice.smith")
        self.assertEqual(result["description"], "SMS - Alice Smith 9451234567")
        self.assertEqual(len(queries), 2)
        self.assertIn("LOWER(mailid) IN", queries[0])
        self.assertIn("m.fkdevice AS associated_device", queries[1])

    def test_precheck_blocks_active_or_associated_number(self):
        rows = sms_only_bulk.parse_sms_bulk_rows("alice.smith@example.com,9451234567")
        def read_sql(host, username, password, sql):
            if "FROM enduser" in sql:
                return [{"userid": "alice.smith", "first_name": "Alice", "last_name": "Smith", "email": "alice.smith@example.com"}]
            return [{"pattern": "9451234567", "route_partition": "ENT_DEVICE_PT", "pattern_usage": "2", "iscallable": "t", "device_count": "1"}]

        with patch.object(sms_only_bulk.sms_only_user, "list_sms_only_patterns", return_value=[]):
            checked = sms_only_bulk.precheck_sms_bulk_rows(rows, "cucm", "operator", "secret", read_sql)
        self.assertEqual(checked["1"]["status"], "number_not_available")

    def test_exact_email_must_resolve_to_one_user(self):
        rows = sms_only_bulk.parse_sms_bulk_rows("alice.smith@example.com,9451234567")
        def read_sql(host, username, password, sql):
            if "FROM enduser" in sql:
                return [
                    {"userid": "alice.smith", "first_name": "Alice", "last_name": "Smith", "email": "alice.smith@example.com"},
                    {"userid": "asmith", "first_name": "Alice", "last_name": "Smith", "email": "alice.smith@example.com"},
                ]
            return []
        with patch.object(sms_only_bulk.sms_only_user, "list_sms_only_patterns", return_value=[]):
            checked = sms_only_bulk.precheck_sms_bulk_rows(rows, "cucm", "operator", "secret", read_sql)
        self.assertEqual(checked["1"]["status"], "ambiguous_email")


class SmsBulkBuildTests(unittest.TestCase):
    def test_build_uses_specific_number_and_same_number_for_ldap(self):
        row = {"number": "9451234567", "userid": "alice.smith", "first_name": "Alice", "last_name": "Smith"}
        with patch.object(sms_only_bulk.requests, "Session") as session_factory, \
             patch.object(sms_only_bulk, "_remove_line") as remove_line, \
             patch.object(sms_only_bulk, "_add_translation_pattern") as add_pattern, \
             patch.object(sms_only_bulk, "update_ad_phone_fields", return_value=(True, "Updated")) as update_ad:
            result = sms_only_bulk.build_sms_for_specific_number("cucm", "operator", "secret", row)

        session_factory.assert_called_once()
        remove_line.assert_called_once()
        self.assertEqual(remove_line.call_args.args[2:], ("9451234567", "ENT_DEVICE_PT"))
        self.assertEqual(add_pattern.call_args.args[2:4], ("9451234567", "SMS - Alice Smith 9451234567"))
        update_ad.assert_called_once_with("alice.smith", "9451234567", {"username": "operator", "password": "secret"})
        self.assertEqual(result["status"], "built")

    def test_pattern_create_failure_attempts_to_restore_inactive_number(self):
        row = {"number": "9451234567", "userid": "alice.smith", "first_name": "Alice", "last_name": "Smith"}
        with patch.object(sms_only_bulk.requests, "Session"), \
             patch.object(sms_only_bulk, "_remove_line"), \
             patch.object(sms_only_bulk, "_add_translation_pattern", side_effect=RuntimeError("AXL failed")), \
             patch.object(sms_only_bulk, "_add_inactive_directory_number") as restore:
            result = sms_only_bulk.build_sms_for_specific_number("cucm", "operator", "secret", row)
        restore.assert_called_once()
        self.assertEqual(result["status"], "needs_review")
        self.assertIn("inactive DN was restored", result["detail"])


class SmsBulkQueueTests(unittest.TestCase):
    def test_persists_results_and_keeps_history(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = sms_only_bulk.BulkSmsTranslationQueue(directory)
            job = queue.submit("cucm-lab", "operator", "alice.smith@example.com,9451234567")
            checked = queue.check(job["id"], "cucm-lab", lambda rows: {"1": {**rows[0], "status": "available", "userid": "alice.smith"}})
            self.assertEqual(checked["status"], "awaiting_confirmation")
            queue.start(job["id"], "cucm-lab", "operator", "BUILD", lambda row: {"status": "built", "pattern_status": "Created", "ldap_status": "Updated", "detail": "Complete"})
            queue.worker.join(timeout=3)
            saved = queue.get(job["id"], "cucm-lab")
            self.assertEqual(saved["status"], "completed")
            self.assertEqual(saved["rows"][0]["status"], "built")
            self.assertEqual(len(queue.history("cucm-lab")), 1)

    def test_restart_marks_running_row_needs_review_and_never_replays_it(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = sms_only_bulk.BulkSmsTranslationQueue(directory)
            job = queue.submit("cucm-lab", "operator", "alice.smith@example.com,9451234567")
            job.update(status="running", started_at=sms_only_bulk._now())
            job["rows"][0].update(status="running", userid="alice.smith")
            queue._save(job)
            recovered = sms_only_bulk.BulkSmsTranslationQueue(directory)
            recovered.recover()
            saved = recovered.get(job["id"], "cucm-lab")
            self.assertEqual(saved["status"], "credentials_required")
            self.assertEqual(saved["rows"][0]["status"], "needs_review")
            self.assertEqual(saved["rows"][0]["pattern_status"], "Unknown")

    def test_invalid_confirmation_does_not_start_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = sms_only_bulk.BulkSmsTranslationQueue(directory)
            job = queue.submit("cucm-lab", "operator", "alice.smith@example.com,9451234567")
            queue.check(job["id"], "cucm-lab", lambda rows: {"1": {**rows[0], "status": "available"}})
            with self.assertRaisesRegex(ValueError, "Type BUILD"):
                queue.start(job["id"], "cucm-lab", "operator", "", lambda row: {})
            self.assertIsNone(queue.worker)


if __name__ == "__main__":
    unittest.main()

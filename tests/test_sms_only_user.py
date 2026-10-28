import csv
import io
import unittest
from unittest.mock import Mock, patch

from toolkit import sms_only_user


class SmsOnlyPatternMatchingTests(unittest.TestCase):
    def test_matches_only_exact_sms_name_extension_partition_and_mask(self):
        rows = [
            {"pattern": "9451234567", "description": "SMS - Alice Smith 9451234567", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"},
            {"pattern": "9451234568", "description": "SMS - Alice Jones 9451234568", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"},
            {"pattern": "9451234569", "description": "SMS - Alice Smith 9451234500", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"},
            {"pattern": "9451234570", "description": "SMS - Alice Smith 9451234570", "route_partition": "ENT_TEAMS_DEVICE_PT", "called_party_transform_mask": "2481009"},
            {"pattern": "9451234571", "description": "SMS - Alice Smith 9451234571", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481001"},
            {"pattern": "9451234572", "description": "TEAMS DID 9451234572 Alice Smith", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"},
        ]

        matches = sms_only_user.find_sms_only_patterns_for_user(rows, "Alice", "Smith")

        self.assertEqual([row["pattern"] for row in matches], ["9451234567"])
        self.assertEqual(matches[0]["extension"], "9451234567")

    def test_pattern_inventory_pages_and_uses_sms_specific_filters(self):
        pages = [
            [
                {"pattern": "9451234567", "description": "SMS - Alice Smith 9451234567", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"},
                {"pattern": "9451234568", "description": "SMS - Bob Jones 9451234568", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"},
            ],
            [
                {"pattern": "9451234569", "description": "SMS - Carol Doe 9451234569", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"},
            ],
        ]
        queries = []

        def read_sql(host, username, password, sql):
            queries.append(sql)
            return pages.pop(0)

        with patch.object(sms_only_user, "SMS_PATTERN_PAGE_SIZE", 2):
            rows = sms_only_user.list_sms_only_patterns("cucm", "user", "pass", read_sql)

        self.assertEqual(len(rows), 3)
        self.assertIn("SKIP 0 FIRST 2", queries[0])
        self.assertIn("SKIP 2 FIRST 2", queries[1])
        self.assertIn("n.description LIKE 'SMS - %'", queries[0])
        self.assertIn("calledpartytransformationmask='2481009'", queries[0])
        self.assertIn("r.name='ENT_DEVICE_PT'", queries[0])

    def test_repeated_pattern_page_is_rejected(self):
        row = {"pattern": "9451234567", "description": "SMS - Alice Smith 9451234567", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009"}
        read_sql = Mock(return_value=[row])
        with patch.object(sms_only_user, "SMS_PATTERN_PAGE_SIZE", 1):
            with self.assertRaisesRegex(RuntimeError, "repeated or invalid page"):
                sms_only_user.list_sms_only_patterns("cucm", "user", "pass", read_sql)


class SmsOnlyCreationTests(unittest.TestCase):
    def test_creates_requested_pattern_and_updates_ldap_with_ten_digit_dn(self):
        with patch.object(sms_only_user, "_get_user_details", return_value={"userid": "alice.smith", "firstName": "Alice", "lastName": "Smith"}), \
             patch.object(sms_only_user, "_choose_available_dn_auto", return_value=("9451234567", "945")), \
             patch.object(sms_only_user, "_remove_line") as remove_line, \
             patch.object(sms_only_user, "_add_translation_pattern") as add_pattern, \
             patch.object(sms_only_user, "update_ad_phone_fields", return_value=(True, "Updated")) as update_ad:
            data, filename = sms_only_user.create_sms_only_user("cucm", "operator", "secret", "alice.smith", "operator", "secret")

        rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
        self.assertTrue(filename.startswith("create_sms_only_user_alice.smith_"))
        remove_line.assert_called_once()
        self.assertEqual(remove_line.call_args.args[2:], ("9451234567", "ENT_DEVICE_PT"))
        add_args = add_pattern.call_args.args
        self.assertEqual(add_args[2], "9451234567")
        self.assertEqual(add_args[3], "SMS - Alice Smith 9451234567")
        self.assertEqual(add_args[4]["transPattern.callingSearchSpaceName"], "Route_Internal_CSS")
        self.assertEqual(add_args[4]["transPattern.routePartitionName"], "ENT_DEVICE_PT")
        self.assertEqual(add_args[4]["transPattern.calledPartyTransformationMask"], "2481009")
        update_ad.assert_called_once_with("alice.smith", "9451234567", {"username": "operator", "password": "secret"})
        self.assertTrue(any(row[0] == "Update AD Phone Fields" and row[1] == "Success" for row in rows))

    def test_rejects_non_ten_digit_allocated_number_before_mutation(self):
        with patch.object(sms_only_user, "_get_user_details", return_value={"userid": "alice.smith", "firstName": "Alice", "lastName": "Smith"}), \
             patch.object(sms_only_user, "_choose_available_dn_auto", return_value=("1234", "123")), \
             patch.object(sms_only_user, "_remove_line") as remove_line:
            data, _filename = sms_only_user.create_sms_only_user("cucm", "operator", "secret", "alice.smith")

        self.assertFalse(any(row[0] == "Delete Inactive Line" for row in list(csv.reader(io.StringIO(data.decode("utf-8"))))))
        remove_line.assert_not_called()


class SmsOnlySeparationTests(unittest.TestCase):
    def test_deletes_exact_match_and_rebuilds_inactive_dn(self):
        match = {"pattern": "9451234567", "description": "SMS - Alice Smith 9451234567", "route_partition": "ENT_DEVICE_PT", "called_party_transform_mask": "2481009", "extension": "9451234567"}
        with patch.object(sms_only_user, "lookup_sms_only_user", return_value={"target_user": "alice.smith", "first_name": "Alice", "last_name": "Smith", "matches": [match]}), \
             patch.object(sms_only_user, "list_sms_only_patterns", return_value=[match]), \
             patch.object(sms_only_user, "_remove_translation_pattern") as remove_pattern, \
             patch.object(sms_only_user, "_add_inactive_directory_number") as add_inactive:
            data, _filename = sms_only_user.remove_sms_only_user("cucm", "operator", "secret", "alice.smith", Mock())

        remove_pattern.assert_called_once()
        self.assertEqual(remove_pattern.call_args.args[2:], ("9451234567", "ENT_DEVICE_PT"))
        add_inactive.assert_called_once()
        self.assertEqual(add_inactive.call_args.args[2:], ("9451234567",))
        rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
        self.assertTrue(any(row[0] == "Delete SMS Translation Pattern" and row[1] == "Success" for row in rows))
        self.assertTrue(any(row[0] == "Rebuild Inactive Directory Number" and row[1] == "Success" for row in rows))

    def test_no_exact_sms_match_leaves_translation_patterns_untouched(self):
        with patch.object(sms_only_user, "lookup_sms_only_user", return_value={"target_user": "alice.smith", "first_name": "Alice", "last_name": "Smith", "matches": []}), \
             patch.object(sms_only_user, "_remove_translation_pattern") as remove_pattern:
            data, _filename = sms_only_user.remove_sms_only_user("cucm", "operator", "secret", "alice.smith", Mock())

        remove_pattern.assert_not_called()
        rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
        self.assertTrue(any(row[0] == "Find SMS Translation Pattern" and row[1] == "Skipped" for row in rows))


if __name__ == "__main__":
    unittest.main()

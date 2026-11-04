import csv
import unittest

from toolkit import unneeded_directory_numbers as numbers


class DirectoryNumberInputTests(unittest.TestCase):
    def test_parses_multiple_delimiters_and_deduplicates(self):
        self.assertEqual(
            numbers.parse_directory_numbers("2142451718, 2142739284\n2142451718;"),
            ["2142451718", "2142739284"],
        )

    def test_rejects_blank_invalid_and_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "Enter one or more"):
            numbers.parse_directory_numbers("")
        with self.assertRaisesRegex(ValueError, "exact 10-digit"):
            numbers.parse_directory_numbers("2142451718, 1234")
        with self.assertRaisesRegex(ValueError, "no more than 1"):
            numbers.parse_directory_numbers("2142451718, 2142739284", limit=1)

    def test_accepts_one_thousand_unique_numbers_and_rejects_one_thousand_one(self):
        batch = [f"{index:010d}" for index in range(1000)]
        self.assertEqual(len(numbers.parse_directory_numbers("\n".join(batch))), 1000)
        with self.assertRaisesRegex(ValueError, "no more than 1000"):
            numbers.parse_directory_numbers("\n".join(batch + ["9999999999"]))

    def test_builds_exact_digit_only_batched_query(self):
        sql = numbers.build_exact_number_sql(["2142451718", "2142739284"])
        self.assertIn("n.dnorpattern IN ('2142451718', '2142739284')", sql)
        self.assertIn("LEFT JOIN devicenumplanmap", sql)
        self.assertIn("n.tkpatternusage = '2'", sql)
        self.assertNotIn("LIKE", sql)


class DirectoryNumberEligibilityTests(unittest.TestCase):
    def test_only_unique_inactive_unassigned_ent_device_dn_is_eligible(self):
        result = numbers.classify_directory_numbers(
            ["2142451718"],
            [{
                "line_id": "line-1",
                "pattern": "2142451718",
                "route_partition": "ENT_DEVICE_PT",
                "is_active": "f",
                "device_id": "",
                "device_name": "",
            }],
        )
        self.assertEqual(result[0]["status"], "Eligible")
        self.assertTrue(result[0]["eligible"])

    def test_active_unknown_and_assigned_lines_are_blocked(self):
        cases = [
            ("t", "", "", "active"),
            ("", "", "", "unknown"),
            ("f", "device-1", "CSF2142451718", "Assigned"),
        ]
        for is_active, device_id, device_name, expected in cases:
            with self.subTest(expected=expected):
                result = numbers.classify_directory_numbers(
                    ["2142451718"],
                    [{
                        "line_id": "line-1",
                        "pattern": "2142451718",
                        "route_partition": "ENT_DEVICE_PT",
                        "is_active": is_active,
                        "device_id": device_id,
                        "device_name": device_name,
                    }],
                )[0]
                self.assertEqual(result["status"], "Blocked")
                self.assertFalse(result["eligible"])

    def test_other_partition_and_duplicate_line_identity_are_blocked(self):
        other_partition = numbers.classify_directory_numbers(
            ["2142451718"],
            [{"line_id": "line-1", "pattern": "2142451718", "route_partition": "ENT_DEVICE_PT", "is_active": "f"},
             {"line_id": "line-2", "pattern": "2142451718", "route_partition": "OTHER_PT", "is_active": "f"}],
        )[0]
        ambiguous = numbers.classify_directory_numbers(
            ["2142451718"],
            [{"line_id": "line-1", "pattern": "2142451718", "route_partition": "ENT_DEVICE_PT", "is_active": "f"},
             {"line_id": "line-2", "pattern": "2142451718", "route_partition": "ENT_DEVICE_PT", "is_active": "f"}],
        )[0]
        self.assertEqual(other_partition["status"], "Blocked")
        self.assertEqual(ambiguous["status"], "Blocked")

    def test_missing_numbers_are_not_found_and_not_eligible(self):
        result = numbers.classify_directory_numbers(["2142451718"], [])[0]
        self.assertEqual(result["status"], "Not Found")
        self.assertFalse(result["eligible"])

    def test_results_csv_lists_action_and_formula_safe_details(self):
        rows = [
            {"pattern": "2142451718", "route_partition": "ENT_DEVICE_PT", "status": "Deleted", "detail": "Removed from CUCM.", "email_sent": True},
            {"pattern": "2142739284", "route_partition": "ENT_DEVICE_PT", "status": "Blocked", "detail": "=review this number", "email_sent": False},
        ]
        text = numbers.results_csv(rows).decode("utf-8-sig")
        parsed = list(csv.reader(text.splitlines()))
        self.assertEqual(parsed[0][0:4], ["Directory Number", "Route Partition", "Result", "Action Taken"])
        self.assertEqual(parsed[1][0], "2142451718")
        self.assertEqual(parsed[1][3], "Removed from CUCM")
        self.assertEqual(parsed[2][4], "'=review this number")


if __name__ == "__main__":
    unittest.main()
import unittest

from toolkit import unity_sql_lookup as sql


def table(rows):
    widths = [25, 20, 20, 20, 20]
    header = "  ".join(value.ljust(width) for value, width in zip(sql.RESULT_COLUMNS, widths))
    divider = "  ".join("-" * width for width in widths)
    values = ["  ".join(value.ljust(width) for value, width in zip(row, widths)) for row in rows]
    return "\n".join([header, divider] + values + ["", "admin:"])


class UnitySqlLookupTests(unittest.TestCase):
    def test_fixed_selects_and_verified_joins(self):
        queries = sql.lookup_queries("717607980490")
        self.assertEqual(len(queries), 4)
        self.assertTrue(all(query.startswith("select first 501") for _, query in queries))
        self.assertIn("s.objectid=a.subscriberobjectid", queries[0][1])
        self.assertIn("h.objectid=t.callhandlerobjectid", queries[1][1])
        self.assertIn("t.extension='717607980490'", queries[1][1])
        self.assertNotIn("timeexpires", queries[1][1].split(" where ")[1])

    def test_injection_and_bad_modes_are_rejected(self):
        for number in ("12", "123';delete", "12%34", "+1234", "", "1234567890123456"):
            with self.assertRaises(ValueError):
                sql.lookup_queries(number)
        with self.assertRaises(ValueError):
            sql.lookup_queries("1234", "unknown")
        self.assertIn("like '%1234%'", sql.lookup_queries("1234", "contains")[1][1])

    def test_parser_preserves_owner_and_full_number(self):
        rows = sql.parse_cli_rows(table([["Phimane Tiaokhiao", "8583147405", "Extension", "717607980490", "Off Hours"]]))
        self.assertEqual(rows[0]["owner_name"], "Phimane Tiaokhiao")
        self.assertEqual(rows[0]["matched_number"], "717607980490")
        self.assertEqual(rows[0]["setting"], "Off Hours")

    def test_errors_and_wrapped_data_are_not_no_matches(self):
        for value in ("SQL error: invalid column", "unrecognized command", table([["Owner", "1000", "Extension", "", "Off Hours"]])):
            with self.assertRaises(sql.UnitySqlError):
                sql.parse_cli_rows(value)
        self.assertEqual(sql.parse_cli_rows("No records found"), [])
        self.assertEqual(sql.parse_cli_rows(table([])), [])

    def test_row_limit_and_command_prefix(self):
        with self.assertRaises(sql.UnitySqlError):
            sql.parse_cli_rows(table([["Owner", "1000", "Extension", "1234", "Standard"]] * 501))
        self.assertTrue(all(command.startswith("run cuc dbquery unitydirdb select ") for _, command in sql.command_templates("1234")))


if __name__ == "__main__":
    unittest.main()
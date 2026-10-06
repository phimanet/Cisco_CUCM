import copy
import json
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from toolkit import cucm_number_usage as usage


def schema_rows():
    tables = {
        "numplan": ["pkid", "dnorpattern", "cfbdestination", "cfnaintdestination", "cfnadestinationint", "calledpartytransformationmask", "callingpartytransformationmask"],
        "callforwarddynamic": ["pkid", "fknumplan", "cfadestination"],
        "devicenumplanmap": ["pkid", "fknumplan", "fkdevice", "e164mask"],
        "remotedestination": ["pkid", "name", "destination"],
        "enduser": ["pkid", "userid", "telephonenumber", "password", "binarydata"],
    }
    return [
        {"table_name": table, "column_name": field, "column_type": "12" if field == "binarydata" else "269"}
        for table, fields in tables.items() for field in fields
    ]


class ContainsTests(unittest.TestCase):
    def test_four_seven_ten_digits_anywhere(self):
        for query in ("5932", "2105932", "2142105932"):
            self.assertEqual(usage._number(query), query)
            for value in ("2142105932", "712142105932", "+1 (214) 210-5932", "214210593299", r"\+12142105932", "number=2142105932;enabled"):
                with self.subTest(query=query, value=value):
                    self.assertTrue(usage._matches(value, query))
            self.assertFalse(usage._matches("2142105933", query))
        self.assertFalse(usage._matches("59 unrelated text 32", "5932"))
        self.assertTrue(usage._matches("5932XXXX", "5932"))

    def test_input_validation_and_no_suffix_truncation(self):
        self.assertEqual(usage._number("+1 (214) 210-5932"), "12142105932")
        for value in ("", "123", "5932' OR 1=1", "21X5932", "1234567890123456"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                usage._number(value)

    def test_sql_candidate_is_superset_of_formatted_match(self):
        where = usage._candidate_where("n", ["mask"], "5932")
        self.assertEqual(where, "n.mask LIKE '%5%9%3%2%'")
        pattern = re.compile(".*5.*9.*3.*2.*", re.S)
        for value in ("+12142105932", "5 (9)-3.2", "593299"):
            self.assertTrue(pattern.fullmatch(value))


class FocusedTests(unittest.TestCase):
    def test_all_forwarding_masks_and_batched_devices(self):
        reads = []

        def execute(session, host, sql):
            reads.append(sql)
            if "systables" in sql:
                return schema_rows()
            base = {"object_id": "line1", "line_id": "line1", "pattern": "1001", "route_partition": "PT"}
            if "FROM numplan" in sql:
                row = dict(base)
                for column, index in re.findall(r"(?:n|cf|dm)\.([a-z0-9_]+) AS value_([0-9]+)", sql):
                    row["value_" + index] = "712142105932" if column != "dnorpattern" else "1001"
                if "e164mask" in sql:
                    row.update(object_id="map1", device_name="CSFTEST")
                return [row]
            if "FROM remotedestination" in sql:
                return [{"object_id": "remote1", "pattern": "Mobile", "destination": "+12142105932"}]
            if "FROM enduser" in sql:
                return [{"object_id": "user1", "pattern": "Test.User", "telephonenumber": "2142105932"}]
            if "FROM devicenumplanmap" in sql:
                return [{"object_id": "line1", "device_name": "CSFTEST"}, {"object_id": "line1", "device_name": "TCTTEST"}]
            raise AssertionError(sql)

        with patch.object(usage, "_execute", execute):
            report = usage.lookup_number_usage("lab", "admin", "not-persisted", "5932")
        self.assertEqual(report["total_matches"], 9)
        self.assertEqual(report["forwarding_matches"], 4)
        self.assertEqual(len(reads), 7)
        self.assertFalse(report["warnings"])
        self.assertNotIn("not-persisted", json.dumps(report))
        self.assertIn("numplan.callingpartytransformationmask", report["checked_fields"])
        external = next(row for row in report["results"] if row["category"] == "External Phone Number Mask")
        self.assertEqual(external["devices"], ["CSFTEST"])
        forward = next(row for row in report["results"] if row["category"] == "Forwarding")
        self.assertEqual(forward["devices"], ["CSFTEST", "TCTTEST"])

    def test_missing_schema_fails_instead_of_no_matches(self):
        with patch.object(usage, "_execute", return_value=[]), self.assertRaises(RuntimeError):
            usage.lookup_number_usage("lab", "admin", "secret", "5932")


class DeepTests(unittest.TestCase):
    def state(self):
        with patch.object(usage, "_execute", return_value=schema_rows()):
            return usage.create_deep_scan("lab", "admin", "not-persisted", "5932")

    def test_catalog_exclusions_and_types(self):
        state = self.state()
        self.assertEqual(len(state["tasks"]), 5)
        self.assertEqual(len(state["skipped_fields"]), 2)
        self.assertNotIn("not-persisted", json.dumps(state))
        self.assertTrue(all(field["text"] for task in state["tasks"] for field in task["fields"]))

    def test_pagination_resume_without_repeating_results(self):
        state = self.state()
        page = [{"object_id": str(index), "value_0": "5932"} for index in range(2)]
        with patch.object(usage, "DEEP_PAGE_SIZE", 2), patch.object(usage, "_execute", return_value=page):
            usage.advance_deep_scan(state, "lab", "admin", "secret")
        self.assertEqual(state["page_offset"], 2)
        self.assertEqual(state["task_index"], 0)
        self.assertEqual(state["total_matches"], 2)
        restored = json.loads(json.dumps(state))
        with patch.object(usage, "_execute", return_value=[{"object_id": "last", "value_0": "5932"}]) as execute:
            usage.advance_deep_scan(restored, "lab", "admin", "secret")
        self.assertIn("SELECT SKIP 2", execute.call_args.args[2])
        self.assertEqual(restored["task_index"], 1)
        self.assertEqual(restored["total_matches"], 3)
        self.assertTrue(restored["checked_fields"])

    def test_failure_is_not_reported_as_checked(self):
        state = self.state()
        with patch.object(usage, "_execute", side_effect=RuntimeError("Permission denied")):
            usage.advance_deep_scan(state, "lab", "admin", "secret")
        self.assertEqual(len(state["failures"]), 1)
        self.assertEqual(state["checked_fields"], [])
        self.assertEqual(state["task_index"], 1)

    def test_numeric_fields_and_tables_without_pkid(self):
        schema = [{"table_name": "countertable", "column_name": "counter", "column_type": "2"}]
        with patch.object(usage, "_execute", return_value=schema):
            state = usage.create_deep_scan("lab", "admin", "secret", "5932")
        with patch.object(usage, "_execute", return_value=[{"value_0": "5932"}]) as execute:
            usage.advance_deep_scan(state, "lab", "admin", "secret")
        self.assertIn("CAST(t.counter AS VARCHAR(64))", execute.call_args.args[2])
        self.assertEqual(state["status"], "completed")
        self.assertIn("no PKID", state["results"][0]["object_id"])
        before = copy.deepcopy(state)
        usage.advance_deep_scan(state, "lab", "admin", "secret")
        self.assertEqual(state, before)


class SqlTests(unittest.TestCase):
    def test_http_200_soap_fault_and_unexpected_response(self):
        for text in ("<Envelope><Fault><faultstring>Denied</faultstring></Fault></Envelope>", "<Envelope/>", "<Envelope><error>SQL error</error></Envelope>"):
            session = SimpleNamespace(post=lambda *args, **kwargs: SimpleNamespace(status_code=200, text=text))
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                usage._execute(session, "lab", "SELECT pkid FROM numplan")

    def test_schema_pagination_and_page_limit(self):
        with patch.object(usage, "PAGE_SIZE", 2), patch.object(usage, "_execute", side_effect=[[{"id": "1"}, {"id": "2"}], [{"id": "3"}]]):
            rows = list(usage._pages(None, "lab", "pkid", "FROM numplan ORDER BY pkid"))
        self.assertEqual(len(rows), 3)
        with patch.object(usage, "PAGE_SIZE", 1), patch.object(usage, "MAX_PAGES", 1), patch.object(usage, "_execute", return_value=[{}]), self.assertRaises(RuntimeError):
            list(usage._pages(None, "lab", "pkid", "FROM numplan ORDER BY pkid"))


if __name__ == "__main__":
    unittest.main()
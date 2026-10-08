import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

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

    def test_ssh_lookup_uses_fixed_queries_and_strict_key_auth(self):
        with tempfile.TemporaryDirectory() as root:
            key_file = os.path.join(root, "unity_sql_key")
            known_hosts_file = os.path.join(root, "known_hosts")
            for path in (key_file, known_hosts_file):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("test")
            environ = {
                "UNITY_SQL_LOOKUP_ENABLED": "true",
                "UNITY_SQL_LOOKUP_LAB_SSH_HOST": "unity-lab.example.test",
                "UNITY_SQL_LOOKUP_SSH_USER": "readonly-admin",
                "UNITY_SQL_LOOKUP_SSH_KEY_FILE": key_file,
                "UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE": known_hosts_file,
            }
            outputs = [table([["Phimane Tiaokhiao", "8583147405", "TransferNumber", "716194104147", "2"]])]
            outputs.extend(["No records found"] * 3)
            calls = []

            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                return SimpleNamespace(returncode=0, stdout=outputs.pop(0), stderr="")

            report = sql.lookup_report("716194104147", unity_host="lascutypl01.ahs.int", runner=runner, environ=environ)

        self.assertEqual(len(calls), 4)
        self.assertEqual(report["rows"][0]["matched_number"], "716194104147")
        self.assertEqual(report["rows"][0]["query_type"], "Mailbox caller input")
        for argv, kwargs in calls:
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("PasswordAuthentication=no", argv)
            self.assertIn("KbdInteractiveAuthentication=no", argv)
            self.assertIn("UserKnownHostsFile=" + known_hosts_file, argv)
            self.assertIn("readonly-admin@unity-lab.example.test", argv)
            self.assertTrue(argv[-1].startswith("'run cuc dbquery unitydirdb select first 501"))
            self.assertEqual(kwargs["timeout"], sql.SSH_TIMEOUT_SECONDS)
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_disabled_or_incomplete_configuration_fails_before_ssh(self):
        self.assertFalse(sql.configuration_status({})["configured"])
        with self.assertRaisesRegex(sql.UnitySqlError, "disabled"):
            sql.lookup_report("1234", unity_host="lascutypl01.ahs.int", runner=lambda *args, **kwargs: self.fail("SSH must not start"), environ={})

    def test_configuration_requires_key_known_hosts_and_ssh(self):
        with tempfile.TemporaryDirectory() as root:
            key_file = os.path.join(root, "unity_sql_key")
            known_hosts_file = os.path.join(root, "known_hosts")
            environ = {
                "UNITY_SQL_LOOKUP_ENABLED": "true",
                "UNITY_SQL_LOOKUP_LAB_SSH_HOST": "unity-lab.example.test",
                "UNITY_SQL_LOOKUP_SSH_USER": "readonly-admin",
                "UNITY_SQL_LOOKUP_SSH_KEY_FILE": key_file,
                "UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE": known_hosts_file,
            }
            with patch.object(sql.shutil, "which", return_value="ssh"):
                status = sql.configuration_status(environ)
                self.assertFalse(status["configured"])
                self.assertIn("UNITY_SQL_LOOKUP_SSH_KEY_FILE (unavailable)", status["missing"])
                self.assertIn("UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE (unavailable)", status["missing"])
                for path in (key_file, known_hosts_file):
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write("test")
                os.chmod(key_file, 0o600)
                self.assertTrue(sql.configuration_status(environ)["configured"])

    def test_atomic_save_failure_retains_previous_report(self):
        first = {
            "schema_version": 1,
            "host": "lascutypl01.ahs.int",
            "query": "1234",
            "mode": "exact",
            "rows": [{"matched_number": "1234"}],
            "coverage": ["Mailbox caller input"],
        }
        replacement = dict(first, rows=[{"matched_number": "5678"}])
        with tempfile.TemporaryDirectory() as root:
            sql.save_report(root, first)
            with patch.object(sql.os, "replace", side_effect=OSError("disk error")):
                with self.assertRaisesRegex(sql.UnitySqlError, "previous report is retained"):
                    sql.save_report(root, replacement)
            self.assertEqual(sql.load_report(root, first["host"])["rows"], first["rows"])


if __name__ == "__main__":
    unittest.main()
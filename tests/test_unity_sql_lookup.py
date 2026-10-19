import ast
import os
import tempfile
import unittest
from pathlib import Path
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
        self.assertEqual(len(queries), 5)
        self.assertTrue(all(query.startswith("select first 501") for _, query in queries))
        alternate_extension = queries[0][1]
        self.assertEqual(queries[0][0], "Mailbox alternate extension")
        self.assertIn("tbl_dtmfaccessid d", alternate_extension)
        self.assertIn("d.dtmfaccessid='717607980490'", alternate_extension)
        self.assertIn("d.parent_globaluserobjectid=u.objectid", alternate_extension)
        self.assertIn("m.userobjectid=u.objectid", alternate_extension)
        self.assertIn("d.idindex not in (0)", alternate_extension)
        self.assertIn("s.objectid=a.subscriberobjectid", queries[1][1])
        self.assertIn("h.objectid=t.callhandlerobjectid", queries[2][1])
        self.assertIn("t.extension='717607980490'", queries[2][1])
        self.assertNotIn("timeexpires", queries[2][1].split(" where ")[1])

    def test_injection_and_bad_modes_are_rejected(self):
        for number in ("12", "123';delete", "12%34", "+1234", "", "1234567890123456"):
            with self.assertRaises(ValueError):
                sql.lookup_queries(number)
        with self.assertRaises(ValueError):
            sql.lookup_queries("1234", "unknown")
        self.assertIn("like '%1234%'", sql.lookup_queries("1234", "contains")[1][1])
        self.assertIn("d.dtmfaccessid like '%1234%'", sql.lookup_queries("1234", "contains")[0][1])

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

    def test_ssh_lookup_uses_fixed_queries_and_pinned_password_auth(self):
        with tempfile.TemporaryDirectory() as root:
            known_hosts_file = os.path.join(root, "known_hosts")
            with open(known_hosts_file, "w", encoding="utf-8") as handle:
                handle.write("test")
            environ = {
                "UNITY_SQL_LOOKUP_ENABLED": "true",
                "UNITY_SQL_LOOKUP_SSH_USER": "readonly.admin@ahs.int",
                "UNITY_SQL_LOOKUP_SSH_PASSWORD": "test-password-not-persisted",
                "UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE": known_hosts_file,
            }
            outputs = [table([["Phimane.Tiaokhiao", "8583147405", "Alternate Extension", "8585236648", "1"]]).encode()]
            outputs.extend([b"No records found"] * 4)
            clients = []
            policy = object()

            class FakeChannel:
                def __init__(self):
                    self.pending = [b"admin:\r\n"]
                    self.commands = []
                    self.closed = False

                def settimeout(self, value):
                    self.timeout = value

                def recv_ready(self):
                    return bool(self.pending)

                def recv(self, size):
                    return self.pending.pop(0)[:size]

                def sendall(self, payload):
                    command = payload.decode("utf-8").strip()
                    self.commands.append(command)
                    echo = ("admin:" + command + "\r\n").encode("utf-8")
                    self.pending.append(echo + outputs.pop(0) + b"\r\nadmin:")

                def close(self):
                    self.closed = True

            class FakeClient:
                def __init__(self):
                    self.channel = FakeChannel()
                    self.closed = False

                def load_host_keys(self, path):
                    self.known_hosts_file = path

                def set_missing_host_key_policy(self, value):
                    self.host_key_policy = value

                def connect(self, **kwargs):
                    self.connection = kwargs

                def invoke_shell(self, **kwargs):
                    self.shell_options = kwargs
                    return self.channel

                def close(self):
                    self.closed = True

            def client_factory():
                client = FakeClient()
                clients.append(client)
                return client

            paramiko_module = SimpleNamespace(SSHClient=client_factory, RejectPolicy=lambda: policy)
            with patch.object(sql.importlib.util, "find_spec", return_value=object()):
                with patch.dict("sys.modules", {"paramiko": paramiko_module}):
                    report = sql.lookup_report(
                        "716194104147",
                        unity_host="lascutypl01.ahs.int",
                        environ=environ,
                    )

        self.assertEqual(len(clients), 1)
        self.assertEqual(report["rows"][0]["matched_number"], "8585236648")
        self.assertEqual(report["rows"][0]["matched_field"], "Alternate Extension")
        self.assertEqual(report["rows"][0]["query_type"], "Mailbox alternate extension")
        self.assertNotIn("test-password-not-persisted", repr(report))
        for client in clients:
            self.assertEqual(client.known_hosts_file, known_hosts_file)
            self.assertIs(client.host_key_policy, policy)
            self.assertEqual(client.connection["hostname"], "lascutypl01.ahs.int")
            self.assertEqual(client.connection["username"], "readonly.admin@ahs.int")
            self.assertEqual(client.connection["password"], "test-password-not-persisted")
            self.assertFalse(client.connection["look_for_keys"])
            self.assertFalse(client.connection["allow_agent"])
            self.assertEqual(client.shell_options, {"term": "vt100", "width": 240, "height": 100})
            self.assertTrue(all(command.startswith("run cuc dbquery unitydirdb") for command in client.channel.commands))
            self.assertTrue(client.closed)

    def test_disabled_or_incomplete_configuration_fails_before_ssh(self):
        self.assertFalse(sql.configuration_status({})["configured"])
        with self.assertRaisesRegex(sql.UnitySqlError, "disabled"):
            sql.lookup_report("1234", unity_host="lascutypl01.ahs.int", environ={})

    def test_configuration_requires_known_hosts_and_paramiko(self):
        with tempfile.TemporaryDirectory() as root:
            known_hosts_file = os.path.join(root, "known_hosts")
            environ = {
                "UNITY_SQL_LOOKUP_ENABLED": "true",
                "UNITY_SQL_LOOKUP_SSH_USER": "readonly-admin",
                "UNITY_SQL_LOOKUP_SSH_PASSWORD": "test-password",
                "UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE": known_hosts_file,
            }
            with patch.object(sql.importlib.util, "find_spec", return_value=object()):
                status = sql.configuration_status(environ)
                self.assertFalse(status["configured"])
                self.assertIn("UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE (unavailable)", status["missing"])
                with open(known_hosts_file, "w", encoding="utf-8") as handle:
                    handle.write("test")
                self.assertTrue(sql.configuration_status(environ)["configured"])

    def test_missing_ssh_credentials_fail_before_client(self):
        with tempfile.TemporaryDirectory() as root:
            known_hosts_file = os.path.join(root, "known_hosts")
            with open(known_hosts_file, "w", encoding="utf-8") as handle:
                handle.write("test")
            environ = {"UNITY_SQL_LOOKUP_ENABLED": "true", "UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE": known_hosts_file}
            with patch.object(sql.importlib.util, "find_spec", return_value=object()):
                with self.assertRaisesRegex(sql.UnitySqlError, "UNITY_SQL_LOOKUP_SSH_USER"):
                    sql.lookup_report("1234", unity_host="lascutypl01.ahs.int", environ=environ)

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


class UnitySqlLookupRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main_path = Path(__file__).resolve().parents[1] / "main.py"
        cls.main_tree = ast.parse(main_path.read_text(encoding="utf-8-sig"))

    def _load_access(self, session, runtime_is_lab):
        scope = {
            "Request": object,
            "_get_auth_session": lambda request: session,
            "_is_admin_user": lambda username: username == "admin",
            "_is_lab_runtime_host": lambda: runtime_is_lab,
        }
        constants = {"LAB_CUCM_HOST", "PROD_CUCM_HOST", "LAB_UNITY_HOST", "PROD_UNITY_HOST"}
        functions = {"_is_lab_host", "_unity_read_access", "_unity_sql_lookup_access"}
        for node in self.main_tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id in constants for target in node.targets
            ):
                exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), scope)
            elif isinstance(node, ast.FunctionDef) and node.name in functions:
                exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), scope)
        return scope["_unity_sql_lookup_access"]

    def test_portal_runtime_does_not_override_selected_unity_environment(self):
        production_session = {"username": "admin", "cucm_host": "lascucmpp01.ahs.int"}
        lab_session = {"username": "admin", "cucm_host": "lascucmpl01.ahs.int"}
        production_access = self._load_access(production_session, runtime_is_lab=True)
        lab_access = self._load_access(lab_session, runtime_is_lab=False)

        self.assertEqual(production_access(None)[0], "SANCUTYP01.ahs.int")
        self.assertEqual(lab_access(None)[0], "lascutypl01.ahs.int")

    def test_lookup_requires_admin_known_portal_and_supported_session_host(self):
        cases = (
            ({"username": "operator", "cucm_host": "lascucmpp01.ahs.int"}, True),
            ({"username": "admin", "cucm_host": "unknown.example"}, True),
            ({"username": "admin", "cucm_host": "lascucmpp01.ahs.int"}, None),
        )
        for session, runtime_is_lab in cases:
            with self.subTest(session=session, runtime_is_lab=runtime_is_lab):
                access = self._load_access(session, runtime_is_lab)
                with self.assertRaises(PermissionError):
                    access(None)


if __name__ == "__main__":
    unittest.main()
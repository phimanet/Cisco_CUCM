import ast
import re
import sqlite3
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from toolkit.edit_line_group_members import find_empty_line_groups


class EmptyLineGroupTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE linegroup (pkid TEXT, name TEXT);
            CREATE TABLE linegroupnumplanmap (pkid TEXT, fklinegroup TEXT, fknumplan TEXT);
            CREATE TABLE routelist (fkdevice TEXT, fklinegroup TEXT);
            CREATE TABLE device (pkid TEXT, name TEXT, tkproduct INTEGER);
            CREATE TABLE typeproduct (enum INTEGER, name TEXT);
            INSERT INTO linegroup VALUES
                ('a', 'Empty & Unreferenced'),
                ('b', 'Empty Referenced'),
                ('c', 'Populated'),
                ('d', 'Empty Route-List Only');
            INSERT INTO linegroupnumplanmap VALUES ('member1', 'c', 'extension-1');
            INSERT INTO routelist VALUES
                ('device1', 'b'),
                ('device2', 'b'),
                ('device1', 'c'),
                ('device3', 'd');
            INSERT INTO device VALUES
                ('device1', 'Hunt List One', 1),
                ('device2', 'Hunt List Two', 1),
                ('device3', 'Route List Only', 2);
            INSERT INTO typeproduct VALUES (1, 'Hunt List'), (2, 'Route List');
        """)
        self.queries = []

    def execute(self, host, username, password, sql):
        self.assertEqual((host, username, password), ("selected-host", "admin", "secret"))
        self.queries.append(sql)
        match = re.match(r"SELECT SKIP (\d+) FIRST (\d+) ", sql)
        self.assertIsNotNone(match)
        offset, limit = match.groups()
        sqlite_sql = "SELECT " + sql[match.end():] + f" LIMIT {limit} OFFSET {offset}"
        return [dict(row) for row in self.db.execute(sqlite_sql)]

    def find(self, executor=None):
        return find_empty_line_groups("selected-host", "admin", "secret", executor or self.execute)

    def test_only_empty_groups_and_all_hunt_list_references_in_one_read(self):
        rows = self.find()
        self.assertEqual([row["line_group_id"] for row in rows], ["a", "b", "d"])
        self.assertEqual(rows[0]["hunt_list_reference_count"], 0)
        self.assertEqual(rows[1]["hunt_lists"], ["Hunt List One", "Hunt List Two"])
        self.assertEqual(rows[1]["hunt_list_reference_count"], 2)
        self.assertEqual(rows[2]["hunt_list_reference_count"], 0)
        self.assertTrue(all(row["extension_count"] == 0 for row in rows))
        self.assertEqual(len(self.queries), 1)

    def test_membership_without_resolvable_extension_still_excludes_group(self):
        self.db.execute("INSERT INTO linegroupnumplanmap VALUES ('member2', 'a', NULL)")
        self.assertEqual([row["line_group_id"] for row in self.find()], ["b", "d"])

    def test_missing_hunt_list_name_is_not_unreferenced(self):
        self.db.execute("UPDATE device SET name = NULL WHERE pkid = 'device2'")
        row = self.find()[1]
        self.assertEqual(row["hunt_list_reference_count"], 2)
        self.assertIn("Name unavailable", row["hunt_lists"])

    def test_pagination_and_empty_inventory(self):
        self.db.executescript("DELETE FROM routelist; DELETE FROM linegroupnumplanmap; DELETE FROM linegroup;")
        self.assertEqual(self.find(), [])
        self.queries.clear()
        self.db.executemany("INSERT INTO linegroup VALUES (?, ?)", [(str(index), f"Group {index}") for index in range(1001)])
        self.assertEqual(len(self.find()), 1001)
        self.assertEqual(len(self.queries), 2)
        self.assertIn("SKIP 1000 FIRST 1000", self.queries[1])

    def test_failure_and_invalid_response_are_not_empty_success(self):
        def fail(*args):
            raise RuntimeError("Permission denied")

        with self.assertRaisesRegex(RuntimeError, "Permission denied"):
            self.find(fail)
        for batch in (None, [{}]):
            with self.assertRaises(RuntimeError):
                self.find(lambda *args: batch)

    def test_repeated_pages_are_rejected(self):
        batch = [{"line_group_id": str(index), "line_group_name": str(index)} for index in range(1000)]
        with self.assertRaisesRegex(RuntimeError, "Repeated"):
            self.find(lambda *args: batch)


class EmptyLineGroupRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8-sig"))
        route = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "page2_empty_line_groups_search_route")
        route.decorator_list = []
        cls.route_code = compile(ast.Module(body=[route], type_ignores=[]), "<empty-line-group-route>", "exec")

    def setUp(self):
        self.finder = Mock(return_value=[{"line_group_name": "Empty"}])
        self.credentials = Mock(return_value=("selected-host", "admin", "secret"))
        self.audit = Mock()
        self.scope = {
            "Request": object,
            "_get_auth_session": lambda request: {"username": "admin"},
            "_is_admin_user": lambda username: username == "admin",
            "_resolve_cucm_credentials": self.credentials,
            "find_empty_line_groups": self.finder,
            "_axl_execute_sql_rows": object(),
            "_append_audit_event": self.audit,
            "logger": Mock(),
            "JSONResponse": lambda content, status_code=200, headers=None: SimpleNamespace(content=content, status_code=status_code, headers=headers),
        }
        exec(self.route_code, self.scope)

    def test_selected_session_host_and_no_credentials_in_response(self):
        result = self.scope["page2_empty_line_groups_search_route"](object())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content["cucm_host"], "selected-host")
        self.assertNotIn("secret", str(result.content))
        self.assertEqual(result.headers["Cache-Control"], "no-store")
        self.finder.assert_called_once_with("selected-host", "admin", "secret", self.scope["_axl_execute_sql_rows"])
        self.audit.assert_called_once()

    def test_anonymous_and_non_admin_denied_before_provider_read(self):
        for session in ({}, {"username": "viewer"}):
            self.scope["_get_auth_session"] = lambda request: session
            result = self.scope["page2_empty_line_groups_search_route"](object())
            self.assertEqual(result.status_code, 403)
        self.finder.assert_not_called()
        self.credentials.assert_not_called()

    def test_provider_failure_is_not_successful_empty_inventory(self):
        self.finder.side_effect = RuntimeError("Provider failure")
        result = self.scope["page2_empty_line_groups_search_route"](object())
        self.assertEqual(result.status_code, 502)
        self.assertFalse(result.content["ok"])
        self.assertNotIn("rows", result.content)
        self.audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
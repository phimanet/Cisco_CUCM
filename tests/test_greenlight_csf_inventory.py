import ast
import csv
import io
import unittest
from pathlib import Path


class GreenlightCsfInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main_path = Path(__file__).resolve().parents[1] / "main.py"
        tree = ast.parse(main_path.read_text(encoding="utf-8-sig"))
        cls.nodes = {}
        names = {
            "GREENLIGHT_CSF_INVENTORY_COLUMNS",
            "GREENLIGHT_CSF_INVENTORY_MAX_PAGES",
            "GREENLIGHT_CSF_INVENTORY_PAGE_SIZE",
            "_greenlight_build_csf_inventory",
            "_greenlight_csf_inventory_csv_bytes",
            "_greenlight_csf_sql_paged",
        }
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in names:
                        cls.nodes[target.id] = node
            elif isinstance(node, ast.FunctionDef) and node.name in names:
                cls.nodes[node.name] = node

    def _load_inventory(self, owner_rows, associated_rows):
        queries = []

        def execute_sql_rows(cucm_host, cucm_user, cucm_pass, query):
            queries.append(query)
            if "AND d.fkenduser IS NULL" in query:
                return associated_rows
            return owner_rows

        scope = {"_axl_execute_sql_rows": execute_sql_rows, "csv": csv, "io": io}
        for name in (
            "GREENLIGHT_CSF_INVENTORY_COLUMNS",
            "GREENLIGHT_CSF_INVENTORY_MAX_PAGES",
            "GREENLIGHT_CSF_INVENTORY_PAGE_SIZE",
            "_greenlight_csf_sql_paged",
            "_greenlight_build_csf_inventory",
            "_greenlight_csf_inventory_csv_bytes",
        ):
            node = self.nodes[name]
            exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), scope)
        return scope, queries

    def test_owner_and_associated_users_include_email_in_rows_and_csv(self):
        owner_rows = [
            {
                "device_name": "CSF1001",
                "device_description": "Owned device",
                "userid": "alice",
                "email": "alice@example.com",
                "first_name": "Alice",
                "last_name": "Owner",
                "title": "Nurse",
                "department": "Clinical",
                "manager_id": "manager1",
                "manager_first": "Morgan",
                "manager_last": "Manager",
                "extension": "8585001001",
            },
            {
                "device_name": "CSF1002",
                "device_description": "Associated device",
                "userid": "",
                "email": "",
                "extension": "8585001002",
            },
        ]
        associated_rows = [
            {
                "device_name": "CSF1002",
                "userid": "bob",
                "email": "bob@example.com",
                "first_name": "Bob",
                "last_name": "Associated",
                "title": "Analyst",
                "department": "Operations",
                "manager_id": "manager2",
                "manager_first": "Taylor",
                "manager_last": "Lead",
            }
        ]
        scope, queries = self._load_inventory(owner_rows, associated_rows)

        rows = scope["_greenlight_build_csf_inventory"]("cucm.example", "admin", "password")
        by_device = {row["device_name"]: row for row in rows}
        self.assertEqual(by_device["CSF1001"]["email"], "alice@example.com")
        self.assertEqual(by_device["CSF1001"]["userid"], "alice")
        self.assertEqual(by_device["CSF1002"]["email"], "bob@example.com")
        self.assertEqual(by_device["CSF1002"]["userid"], "bob")
        self.assertTrue(all("u.mailid AS email" in query for query in queries))

        csv_rows = list(csv.reader(io.StringIO(scope["_greenlight_csf_inventory_csv_bytes"](rows).decode("utf-8"))))
        email_index = csv_rows[0].index("Email Address")
        userid_index = csv_rows[0].index("Username")
        self.assertEqual(csv_rows[1][email_index], "alice@example.com")
        self.assertEqual(csv_rows[2][email_index], "bob@example.com")
        self.assertEqual([csv_rows[1][userid_index], csv_rows[2][userid_index]], ["alice", "bob"])


if __name__ == "__main__":
    unittest.main()
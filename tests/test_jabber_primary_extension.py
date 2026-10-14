import ast
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from toolkit import jabber_primary_extension as finder


class JabberPrimaryExtensionTests(unittest.TestCase):
    def row(self, userid, device, extension="", partition="", first="Jakilah", last="Smith", email="jakilah.smith@example.com"):
        return {
            "userid": userid,
            "first_name": first,
            "last_name": last,
            "email": email,
            "device_name": device,
            "jabber_extension": extension,
            "jabber_partition": partition,
        }

    def test_finds_primary_blank_jabber_users_and_ent_partition_fix_candidate(self):
        owner_rows = [self.row("Jakilah.Smith", "CSF2143470269", "2143470269", "ENT_DEVICE_PT")]
        associated_rows = [self.row("Jakilah.Smith", "TCT2143470269", "2143470200", "OTHER_PT")]
        queries = []

        def execute_sql(host, username, password, sql):
            queries.append(sql)
            return associated_rows if "enduserdevicemap edm" in sql else owner_rows

        results = finder.find_missing_primary_extension_users("cucm.example", "admin", "pass", execute_sql)

        self.assertEqual(len(results), 1)
        user = results[0]
        self.assertEqual(user["userid"], "Jakilah.Smith")
        self.assertEqual(user["email"], "jakilah.smith@example.com")
        self.assertEqual(user["primary_extension"], "")
        self.assertEqual(user["jabber_devices"], ["CSF2143470269", "TCT2143470269"])
        self.assertEqual(user["eligible_extensions"], ["2143470269"])
        self.assertTrue(user["fix_allowed"])
        self.assertTrue(all("tkdnusage = 1" in query for query in queries))
        self.assertTrue(all("ENT_DEVICE_PT" not in query or "jabber_partition" in query for query in queries))

    def test_fix_is_blocked_for_ambiguous_or_missing_ent_partition_extensions(self):
        owner_rows = [
            self.row("Jakilah.Smith", "CSF2143470269", "2143470269", "ENT_DEVICE_PT"),
            self.row("Jakilah.Smith", "CSF2143470270", "2143470270", "ENT_DEVICE_PT"),
        ]

        results = finder.find_missing_primary_extension_users(
            "cucm.example", "admin", "pass",
            lambda host, username, password, sql: owner_rows if "INNER JOIN device d" in sql else [],
        )

        self.assertEqual(results[0]["eligible_extensions"], ["2143470269", "2143470270"])
        self.assertFalse(results[0]["fix_allowed"])
        self.assertIn("Multiple Jabber lines", results[0]["fix_reason"])

    def test_fix_uses_only_updateuser_primary_extension_and_verifies_readback(self):
        current_profiles = [("", ""), ("2143470269", "ENT_DEVICE_PT")]

        def profile_xml(pattern, partition):
            return (
                "<Envelope><Body><getUserResponse><return><user><userid>Jakilah.Smith</userid>"
                f"<primaryExtension><pattern>{pattern}</pattern><routePartitionName>{partition}</routePartitionName></primaryExtension>"
                "</user></return></getUserResponse></Body></Envelope>"
            )

        class FakeResponse:
            status_code = 200

            def __init__(self, text):
                self.text = text

        class FakeSession:
            def __init__(self):
                self.posts = []

            def post(self, url, data, **kwargs):
                self.posts.append(data.decode("utf-8"))
                if "<axl:getUser" in self.posts[-1]:
                    pattern, partition = current_profiles.pop(0)
                    return FakeResponse(profile_xml(pattern, partition))
                return FakeResponse("<Envelope><Body><updateUserResponse><return/></updateUserResponse></Body></Envelope>")

        session = FakeSession()
        result = finder.fix_primary_extension(
            "cucm.example", "admin", "pass", "Jakilah.Smith", "2143470269",
            session_factory=lambda: session,
        )

        self.assertEqual(result, {"userid": "Jakilah.Smith", "extension": "2143470269", "partition": "ENT_DEVICE_PT", "verified": True})
        update_xml = next(payload for payload in session.posts if "<axl:updateUser" in payload)
        self.assertIn("<primaryExtension><pattern>2143470269</pattern><routePartitionName>ENT_DEVICE_PT</routePartitionName></primaryExtension>", update_xml)
        self.assertNotIn("<associatedDevices>", update_xml)
        self.assertEqual(sum("<axl:getUser" in payload for payload in session.posts), 2)

    def test_fix_refuses_to_overwrite_existing_primary_extension(self):
        class FakeResponse:
            status_code = 200
            text = (
                "<Envelope><Body><getUserResponse><return><user><userid>Jakilah.Smith</userid>"
                "<primaryExtension><pattern>8585236648</pattern><routePartitionName>ENT_DEVICE_PT</routePartitionName>"
                "</primaryExtension></user></return></getUserResponse></Body></Envelope>"
            )

        class FakeSession:
            posts = []

            def post(self, url, data, **kwargs):
                self.posts.append(data.decode("utf-8"))
                return FakeResponse()

        session = FakeSession()
        with self.assertRaisesRegex(RuntimeError, "no longer blank"):
            finder.fix_primary_extension(
                "cucm.example", "admin", "pass", "Jakilah.Smith", "2143470269",
                session_factory=lambda: session,
            )
        self.assertFalse(any("<axl:updateUser" in payload for payload in session.posts))


class Page2JabberPrimaryExtensionRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main_path = Path(__file__).resolve().parents[1] / "main.py"
        tree = ast.parse(main_path.read_text(encoding="utf-8-sig"))
        names = {
            "_page2_jabber_primary_credentials",
            "page2_jabber_primary_extension_search_route",
            "page2_jabber_primary_extension_fix_route",
        }
        cls.functions = {
            node.name: node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in names
        }

    def setUp(self):
        self.session = {"username": "admin", "cucm_host": "cucm.example"}
        self.audit = []
        self.rows = [{
            "userid": "Jakilah.Smith",
            "first_name": "Jakilah",
            "last_name": "Smith",
            "name": "Jakilah Smith",
            "email": "jakilah.smith@example.com",
            "primary_extension": "",
            "jabber_devices": ["CSF2143470269"],
            "jabber_lines": [{"device_name": "CSF2143470269", "extension": "2143470269", "partition": "ENT_DEVICE_PT"}],
            "eligible_extensions": ["2143470269"],
            "fix_allowed": True,
            "fix_extension": "2143470269",
            "fix_reason": "",
        }]

        def response(content=None, status_code=200, headers=None, **kwargs):
            return SimpleNamespace(content=content, status_code=status_code, headers=headers or {})

        scope = {
            "Request": object,
            "Form": lambda default: default,
            "JSONResponse": response,
            "jabber_primary_extension": finder,
            "_get_auth_session": lambda request: self.session,
            "_is_admin_user": lambda username: username == "admin",
            "_resolve_cucm_credentials": lambda request, host, user, password: ("cucm.example", "admin", "secret"),
            "_axl_execute_sql_rows": lambda host, user, password, sql: [],
            "_append_audit_event": lambda **kwargs: self.audit.append(kwargs),
            "logger": SimpleNamespace(warning=lambda *args: None),
        }
        for name in (
            "_page2_jabber_primary_credentials",
            "page2_jabber_primary_extension_search_route",
            "page2_jabber_primary_extension_fix_route",
        ):
            function = ast.Module(body=[self.functions[name]], type_ignores=[])
            node = self.functions[name]
            node.decorator_list = []
            exec(compile(function, "main.py", "exec"), scope)
        self.scope = scope
        self.scope["_axl_execute_sql_rows"] = self._execute_sql

    def _execute_sql(self, host, user, password, query):
        if "enduserdevicemap edm" in query:
            return []
        return [{
            "userid": "Jakilah.Smith",
            "first_name": "Jakilah",
            "last_name": "Smith",
            "email": "jakilah.smith@example.com",
            "device_name": "CSF2143470269",
            "jabber_extension": "2143470269",
            "jabber_partition": "ENT_DEVICE_PT",
        }]

    def test_fetch_route_returns_jakilah_missing_primary_candidate(self):
        result = self.scope["page2_jabber_primary_extension_search_route"](None)

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content["rows"][0]["userid"], "Jakilah.Smith")
        self.assertEqual(result.content["rows"][0]["fix_extension"], "2143470269")
        self.assertEqual(self.audit[0]["action"], "page2_jabber_primary_extension_search")

    def test_fix_route_rechecks_and_updates_only_unique_candidate(self):
        with patch.object(finder, "fix_primary_extension", return_value={
            "userid": "Jakilah.Smith", "extension": "2143470269", "partition": "ENT_DEVICE_PT", "verified": True,
        }) as update:
            result = self.scope["page2_jabber_primary_extension_fix_route"](
                None, userid="Jakilah.Smith", extension="2143470269",
            )

        self.assertEqual(result.status_code, 200)
        update.assert_called_once_with("cucm.example", "admin", "secret", "Jakilah.Smith", "2143470269")
        self.assertEqual(self.audit[0]["action"], "page2_jabber_primary_extension_fixed")

    def test_fix_route_rejects_ambiguous_candidates_without_writing(self):
        original = self._execute_sql

        def ambiguous_sql(host, user, password, query):
            if "enduserdevicemap edm" in query:
                return []
            return original(host, user, password, query) + [{
                "userid": "Jakilah.Smith", "first_name": "Jakilah", "last_name": "Smith",
                "email": "jakilah.smith@example.com", "device_name": "CSF2143470270",
                "jabber_extension": "2143470270", "jabber_partition": "ENT_DEVICE_PT",
            }]

        self.scope["_axl_execute_sql_rows"] = ambiguous_sql
        with patch.object(finder, "fix_primary_extension") as update:
            result = self.scope["page2_jabber_primary_extension_fix_route"](
                None, userid="Jakilah.Smith", extension="2143470269",
            )

        self.assertEqual(result.status_code, 409)
        update.assert_not_called()

    def test_search_route_requires_admin(self):
        self.session["username"] = "not-admin"
        result = self.scope["page2_jabber_primary_extension_search_route"](None)
        self.assertEqual(result.status_code, 403)


if __name__ == "__main__":
    unittest.main()
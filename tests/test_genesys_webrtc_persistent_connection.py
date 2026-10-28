import ast
import datetime
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


MAIN_PATH = Path(__file__).resolve().parents[1] / "main.py"


def load_top_level_functions(names, scope):
    tree = ast.parse(MAIN_PATH.read_text(encoding="utf-8-sig"))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    for node in nodes:
        node.decorator_list = []
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "main.py", "exec"), scope)


class PersistentWebRTCInventoryTests(unittest.TestCase):
    def setUp(self):
        self.stations = [
            {"id": "station-on-1", "name": "Alice Station", "type": "inin_webrtc_softphone", "webRtcUserId": "user-1", "webRtcPersistentEnabled": True},
            {"id": "station-off", "name": "Off Station", "type": "inin_webrtc_softphone", "webRtcUserId": "user-2", "webRtcPersistentEnabled": False},
            {"id": "station-unknown", "name": "Unknown Station", "type": "inin_webrtc_softphone", "webRtcUserId": "user-3"},
            {"id": "station-on-2", "name": "Unmatched Station", "type": "inin_webrtc_softphone", "webRtcUserId": "user-4", "webRtcPersistentEnabled": True},
        ]
        self.phones = [
            {"id": "phone-1", "name": "Alice WebRTC", "webRtcUser": {"id": "user-1"}, "phoneBaseSettings": {"name": "WebRTC Base"}},
        ]
        self.calls = []

        def get_json(api_base, access_token, path, params=None):
            self.calls.append((path, dict(params or {})))
            source = self.stations if path == "/api/v2/stations" else self.phones
            page_size = int(params["pageSize"])
            page_number = int(params["pageNumber"])
            start = (page_number - 1) * page_size
            entities = source[start:start + page_size]
            return True, {"entities": entities, "pageCount": (len(source) + page_size - 1) // page_size}, ""

        self.scope = {
            "_genesys_region_to_urls": lambda region: (region, "https://login.example", "https://api.example"),
            "_genesys_get_json": get_json,
            "GENESYS_PERSISTENT_WEBRTC_PAGE_SIZE": 2,
            "GENESYS_PERSISTENT_WEBRTC_MAX_PAGES": 10,
        }
        load_top_level_functions({"_genesys_list_webrtc_persistent_phones"}, self.scope)

    def test_lists_configured_on_webrtc_only_and_reports_unknown_and_unmatched(self):
        result = self.scope["_genesys_list_webrtc_persistent_phones"]("usw2", "token")

        self.assertTrue(result["ok"])
        self.assertEqual(result["stations_scanned"], 4)
        self.assertEqual(result["webrtc_stations"], 4)
        self.assertEqual(result["persistent_on_stations"], 2)
        self.assertEqual(result["persistent_off_stations"], 1)
        self.assertEqual(result["setting_unknown_stations"], 1)
        self.assertEqual(result["phones_scanned"], 1)
        self.assertEqual(result["unmatched_enabled_stations"], 1)
        self.assertEqual([row["phone_name"] for row in result["rows"]], ["Alice WebRTC", "Unmatched Station"])
        self.assertEqual(result["rows"][0]["phone_base_settings_name"], "WebRTC Base")
        self.assertEqual(result["rows"][1]["phone_mapping_status"], "Station found; Phone Management record not returned")
        self.assertEqual(sum(path == "/api/v2/stations" for path, _ in self.calls), 2)
        self.assertEqual(sum(path == "/api/v2/telephony/providers/edges/phones" for path, _ in self.calls), 1)
        self.assertTrue(all(params.get("webRtcUserId") == "*" for _, params in self.calls))

    def test_inventory_failure_does_not_claim_empty_success(self):
        self.scope["_genesys_get_json"] = lambda *args, **kwargs: (False, {}, "Forbidden")
        result = self.scope["_genesys_list_webrtc_persistent_phones"]("usw2", "token")

        self.assertFalse(result["ok"])
        self.assertIn("WebRTC station inventory failed", result["error"])


class PersistentWebRTCRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.functions = {
            "genesys_webrtc_persistent_connection_route",
        }

    def setUp(self):
        self.session = {"username": "genesys.admin", "cucm_host": "lab"}
        self.audit = []
        self.token_calls = []
        self.inventory_calls = []
        response = lambda content, status_code=200, headers=None: SimpleNamespace(content=content, status_code=status_code, headers=headers or {})
        self.scope = {
            "Request": object,
            "JSONResponse": response,
            "_get_auth_session": lambda request: self.session,
            "GENESYS_CLOUD_REGION": "usw2",
            "GENESYS_CLIENT_ID": "client",
            "GENESYS_CLIENT_SECRET": "secret",
            "_genesys_get_access_token": lambda region, client_id, client_secret: self.token_calls.append((region, client_id, client_secret)) or {"ok": True, "region": "usw2", "access_token": "token"},
            "_genesys_list_webrtc_persistent_phones": lambda region, access_token: self.inventory_calls.append((region, access_token)) or {"ok": True, "region": region, "webrtc_stations": 1, "persistent_on_stations": 1, "phones_scanned": 1, "unmatched_enabled_stations": 0, "rows": []},
            "_append_audit_event": lambda **kwargs: self.audit.append(kwargs),
            "datetime": datetime,
            "logger": SimpleNamespace(warning=lambda *args: None),
        }
        load_top_level_functions(self.functions, self.scope)

    def test_route_requires_portal_session(self):
        self.session = {}
        result = self.scope["genesys_webrtc_persistent_connection_route"](None)

        self.assertEqual(result.status_code, 401)
        self.assertEqual(self.token_calls, [])

    def test_route_uses_read_only_inventory_and_audits_counts(self):
        result = self.scope["genesys_webrtc_persistent_connection_route"](None)

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content["persistent_on_stations"], 1)
        self.assertEqual(self.inventory_calls, [("usw2", "token")])
        self.assertEqual(self.audit[0]["action"], "genesys_webrtc_persistent_connection_inventory")
        self.assertIn("persistent_on=1", self.audit[0]["target"])


if __name__ == "__main__":
    unittest.main()

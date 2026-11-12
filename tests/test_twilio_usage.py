import ast
import csv
import datetime
import io
import json
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from toolkit import twilio_usage


ACCOUNT_SID = "AC" + "a" * 32
ROOT_SID = "AC" + "b" * 32


def _response(record, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.json.return_value = {"usage_records": [record]}
    return response


def _message_page(messages, next_page_uri=None):
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"messages": messages, "next_page_uri": next_page_uri}
    return response


class TwilioUsageTests(unittest.TestCase):
    def test_error_report_csv_is_formula_safe_and_omits_message_body(self):
        report = {
            "account_name": "Test Account",
            "complete": True,
            "pages_read": 1,
            "error": "",
            "rows": [{
                "date_sent": "2026-11-11T16:00:00+00:00",
                "to": "+12125550101",
                "error_code": 30003,
                "status": "undelivered",
                "from": "=malicious@example.com",
                "message_sid": "SM" + "1" * 32,
                "body": "must not be attached",
            }],
        }

        with patch.object(twilio_usage, "ZoneInfo", return_value=datetime.timezone(datetime.timedelta(hours=-6), "CST")):
            rows = list(csv.reader(io.StringIO(twilio_usage.build_outbound_message_errors_csv(report).decode("utf-8"))))

        self.assertEqual(rows[0][1], "Sent (CST/CDT)")
        self.assertEqual(rows[1][1], "2026-11-11 10:00:00 CST")
        self.assertEqual(rows[1][2], "'+12125550101")
        self.assertEqual(rows[1][5], "'=malicious@example.com")
        self.assertNotIn("must not be attached", str(rows))

    def test_read_outbound_sms_usage_scopes_account_and_dates(self):
        response = _response({
            "account_sid": ACCOUNT_SID,
            "category": "sms-outbound",
            "count": "1234",
            "count_unit": "messages",
            "as_of": "2026-11-11T08:00:00Z",
        })
        with patch.object(twilio_usage.requests, "get", return_value=response) as get:
            result = twilio_usage.read_outbound_sms_usage(
                ACCOUNT_SID, ROOT_SID, "secret", "2026-11-01", "2026-11-10"
            )

        self.assertEqual(result["count"], 1234)
        self.assertEqual(result["count_unit"], "messages")
        self.assertEqual(get.call_args.args[0], (
            f"https://api.twilio.com/2010-04-01/Accounts/{ACCOUNT_SID}/Usage/Records.json"
        ))
        self.assertEqual(get.call_args.kwargs["params"], {
            "Category": "sms-outbound",
            "StartDate": "2026-11-01",
            "EndDate": "2026-11-10",
        })
        self.assertEqual(get.call_args.kwargs["auth"], (ROOT_SID, "secret"))
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_read_outbound_sms_usage_rejects_mismatched_account(self):
        response = _response({
            "account_sid": ROOT_SID,
            "category": "sms-outbound",
            "count": "12",
            "count_unit": "messages",
        })
        with patch.object(twilio_usage.requests, "get", return_value=response):
            with self.assertRaises(twilio_usage.TwilioUsageError):
                twilio_usage.read_outbound_sms_usage(
                    ACCOUNT_SID, ROOT_SID, "secret", "2026-11-01", "2026-11-10"
                )

    def test_read_outbound_sms_usage_rejects_invalid_count(self):
        response = _response({
            "account_sid": ACCOUNT_SID,
            "category": "sms-outbound",
            "count": "12.5",
            "count_unit": "messages",
        })
        with patch.object(twilio_usage.requests, "get", return_value=response):
            with self.assertRaises(twilio_usage.TwilioUsageError):
                twilio_usage.read_outbound_sms_usage(
                    ACCOUNT_SID, ROOT_SID, "secret", "2026-11-01", "2026-11-10"
                )

    def test_read_outbound_sms_usage_rejects_reversed_dates_without_request(self):
        with patch.object(twilio_usage.requests, "get") as get:
            with self.assertRaises(twilio_usage.TwilioUsageError):
                twilio_usage.read_outbound_sms_usage(
                    ACCOUNT_SID, ROOT_SID, "secret", "2026-11-10", "2026-11-01"
                )
        get.assert_not_called()

    def test_build_report_sums_unique_parent_and_subaccount_rows(self):
        child_sid = "AC" + "c" * 32
        second_root_sid = "AC" + "d" * 32
        roots = [
            {"sid": ROOT_SID, "name": "Parent One", "auth_token": "root-secret"},
            {"sid": second_root_sid, "name": "Parent Two", "auth_token": "second-secret"},
        ]

        def list_accounts(root):
            if root["sid"] == ROOT_SID:
                return {"ok": True, "accounts": [
                    {"sid": ROOT_SID, "friendly_name": "Parent One", "account_type": "Root Account"},
                    {"sid": child_sid, "friendly_name": "Child One", "account_type": "Subaccount"},
                    {"sid": second_root_sid, "friendly_name": "Parent Two as child", "account_type": "Subaccount"},
                ]}
            return {"ok": True, "accounts": [
                {"sid": second_root_sid, "friendly_name": "Parent Two", "account_type": "Root Account"},
            ]}

        calls = []

        def read_usage(account_sid, auth_sid, auth_token, start_date, end_date):
            calls.append((account_sid, auth_sid, auth_token))
            return {"count": {ROOT_SID: 10, child_sid: 20, second_root_sid: 30}[account_sid], "count_unit": "messages", "as_of": "now"}

        report = twilio_usage.build_outbound_sms_usage_report(
            roots, [], list_accounts, "2026-11-01", "2026-11-10", read_usage
        )

        self.assertEqual(report["total_count"], 60)
        self.assertEqual(report["account_count"], 3)
        self.assertTrue(report["coverage_complete"])
        self.assertEqual(len(calls), 3)
        self.assertIn((child_sid, ROOT_SID, "root-secret"), calls)
        self.assertIn((second_root_sid, second_root_sid, "second-secret"), calls)

    def test_build_report_keeps_known_counts_and_marks_failures_partial(self):
        child_sid = "AC" + "c" * 32
        roots = [{"sid": ROOT_SID, "name": "Parent", "auth_token": "secret"}]

        def list_accounts(root):
            return {"ok": True, "accounts": [
                {"sid": ROOT_SID, "friendly_name": "Parent", "account_type": "Root Account"},
                {"sid": child_sid, "friendly_name": "Child", "account_type": "Subaccount"},
            ]}

        def read_usage(account_sid, auth_sid, auth_token, start_date, end_date):
            if account_sid == child_sid:
                raise twilio_usage.TwilioUsageError("Twilio outbound SMS usage query failed (HTTP 403).")
            return {"count": 14, "count_unit": "messages", "as_of": "now"}

        report = twilio_usage.build_outbound_sms_usage_report(
            roots, [], list_accounts, "2026-11-01", "2026-11-10", read_usage
        )

        self.assertEqual(report["total_count"], 14)
        self.assertFalse(report["coverage_complete"])
        self.assertEqual(len(report["errors"]), 1)
        child_row = next(row for row in report["rows"] if row["account_sid"] == child_sid)
        self.assertIsNone(child_row["count"])
        self.assertEqual(child_row["status"], "Lookup Failed")

    def test_error_search_filters_codes_and_outbound_and_paginates(self):
        account = {"sid": ACCOUNT_SID, "auth_sid": ROOT_SID, "auth_token": "secret", "account_name": "Child"}
        first_page = _message_page([
            {"account_sid": ACCOUNT_SID, "sid": "SM" + "1" * 32, "direction": "outbound-api", "error_code": 30003, "date_sent": "Wed, 11 Nov 2026 16:00:00 +0000", "from": "+12125550100", "to": "+12125550101", "status": "undelivered", "body": "must not be returned"},
            {"account_sid": ACCOUNT_SID, "sid": "SM" + "2" * 32, "direction": "inbound", "error_code": 30004, "date_sent": "Wed, 11 Nov 2026 16:01:00 +0000", "from": "+12125550102", "to": "+12125550100"},
            {"account_sid": ACCOUNT_SID, "sid": "SM" + "3" * 32, "direction": "outbound-api", "error_code": 30007, "date_sent": "Wed, 11 Nov 2026 16:02:00 +0000", "from": "+12125550100", "to": "+12125550103"},
            {"account_sid": ACCOUNT_SID, "sid": "SM" + "7" * 32, "direction": "outbound-api", "error_code": 0, "date_sent": "Wed, 11 Nov 2026 16:03:00 +0000", "from": "+12125550100", "to": "+12125550107"},
            {"account_sid": ACCOUNT_SID, "sid": "SM" + "8" * 32, "direction": "outbound-api", "error_code": 9999, "date_sent": "Wed, 11 Nov 2026 16:04:00 +0000", "from": "+12125550100", "to": "+12125550108"},
            {"account_sid": ACCOUNT_SID, "sid": "SM" + "9" * 32, "direction": "outbound-api", "error_code": 100000, "date_sent": "Wed, 11 Nov 2026 16:05:00 +0000", "from": "+12125550100", "to": "+12125550109"},
        ], f"/2010-04-01/Accounts/{ACCOUNT_SID}/Messages.json?PageToken=next")
        second_page = _message_page([
            {"account_sid": ACCOUNT_SID, "sid": "SM" + "4" * 32, "direction": "outbound-reply", "error_code": "21610", "date_sent": "Wed, 11 Nov 2026 16:03:00 +0000", "from": "+12125550100", "to": "+12125550104", "status": "undelivered"},
        ])
        with patch.object(twilio_usage.requests, "get", side_effect=[first_page, second_page]) as get:
            result = twilio_usage.search_outbound_message_errors(
                account, "2026-11-11T15:00:00Z", "2026-11-11T17:00:00Z"
            )

        self.assertTrue(result["complete"])
        self.assertEqual(result["pages_read"], 2)
        self.assertEqual([row["error_code"] for row in result["rows"]], [21610, 30007, 30003])
        self.assertEqual({row["to"] for row in result["rows"]}, {"+12125550101", "+12125550103", "+12125550104"})
        self.assertTrue(all("body" not in row for row in result["rows"]))
        self.assertEqual(get.call_args_list[0].kwargs["params"], {
            "DateSent>=": "2026-11-11T15:00:00Z",
            "DateSent<=": "2026-11-11T17:00:00Z",
            "PageSize": 100,
        })
        self.assertEqual(get.call_args_list[0].kwargs["auth"], (ROOT_SID, "secret"))
        self.assertIsNone(get.call_args_list[1].kwargs["params"])

    def test_error_search_rejects_cross_account_pagination(self):
        account = {"sid": ACCOUNT_SID, "auth_sid": ROOT_SID, "auth_token": "secret", "account_name": "Child"}
        page = _message_page([], f"/2010-04-01/Accounts/{ROOT_SID}/Messages.json?PageToken=wrong")
        with patch.object(twilio_usage.requests, "get", return_value=page):
            result = twilio_usage.search_outbound_message_errors(
                account, "2026-11-11T15:00:00Z", "2026-11-11T17:00:00Z"
            )
        self.assertFalse(result["complete"])
        self.assertIn("different-account", result["error"])

    def test_error_search_requires_timezone_aware_range(self):
        account = {"sid": ACCOUNT_SID, "auth_sid": ROOT_SID, "auth_token": "secret", "account_name": "Child"}
        with patch.object(twilio_usage.requests, "get") as get:
            with self.assertRaises(twilio_usage.TwilioUsageError):
                twilio_usage.search_outbound_message_errors(
                    account, "2026-11-11T15:00", "2026-11-11T17:00Z"
                )
        get.assert_not_called()

    def test_error_search_marks_page_limit_as_incomplete(self):
        account = {"sid": ACCOUNT_SID, "auth_sid": ROOT_SID, "auth_token": "secret", "account_name": "Child"}
        page = _message_page([], f"/2010-04-01/Accounts/{ACCOUNT_SID}/Messages.json?PageToken=next")
        with patch.object(twilio_usage, "MESSAGE_ERROR_MAX_PAGES", 1), patch.object(twilio_usage.requests, "get", return_value=page):
            result = twilio_usage.search_outbound_message_errors(
                account, "2026-11-11T15:00:00Z", "2026-11-11T17:00:00Z"
            )
        self.assertFalse(result["complete"])
        self.assertIn("Page limit reached", result["error"])

    def test_error_search_can_resume_one_page_per_request(self):
        account = {"sid": ACCOUNT_SID, "auth_sid": ROOT_SID, "auth_token": "secret", "account_name": "Child"}
        next_uri = f"/2010-04-01/Accounts/{ACCOUNT_SID}/Messages.json?PageToken=next"
        pages = [
            _message_page([
                {"account_sid": ACCOUNT_SID, "sid": "SM" + "5" * 32, "direction": "outbound-api", "error_code": 30003, "date_sent": "Wed, 11 Nov 2026 16:00:00 +0000", "from": "+12125550100", "to": "+12125550105", "status": "undelivered"},
            ], next_uri),
            _message_page([
                {"account_sid": ACCOUNT_SID, "sid": "SM" + "6" * 32, "direction": "outbound-api", "error_code": 21610, "date_sent": "Wed, 11 Nov 2026 16:01:00 +0000", "from": "+12125550100", "to": "+12125550106", "status": "undelivered"},
            ]),
        ]
        with patch.object(twilio_usage.requests, "get", side_effect=pages) as get:
            first = twilio_usage.search_outbound_message_errors(
                account, "2026-11-11T15:00:00Z", "2026-11-11T17:00:00Z", page_limit=1
            )
            second = twilio_usage.search_outbound_message_errors(
                account, "2026-11-11T15:00:00Z", "2026-11-11T17:00:00Z",
                next_uri=first["next_uri"], pages_read=first["pages_read"], page_limit=1,
            )

        self.assertFalse(first["complete"])
        self.assertEqual(len(first["rows"]), 1)
        self.assertTrue(second["complete"])
        self.assertEqual(second["pages_read"], 2)
        self.assertEqual(second["rows"][0]["error_code"], 21610)
        self.assertIsNone(get.call_args_list[1].kwargs["params"])


class TwilioErrorReportEmailRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / "main.py"
        tree = ast.parse(source.read_text(encoding="utf-8-sig"))
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "twilio_error_report_email_route")
        cls.route_node = ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=[],
            returns=node.returns,
            type_comment=None,
        )

    def setUp(self):
        self.send_email = Mock()
        self.audit = Mock()
        self.is_admin = Mock(return_value=True)
        timezone_patch = patch.object(twilio_usage, "ZoneInfo", return_value=datetime.timezone(datetime.timedelta(hours=-6), "CST"))
        timezone_patch.start()
        self.addCleanup(timezone_patch.stop)
        self.scope = {
            "Request": object,
            "Form": lambda value: value,
            "JSONResponse": lambda content, status_code=200, headers=None: SimpleNamespace(content=content, status_code=status_code, headers=headers),
            "json": json,
            "re": re,
            "twilio_usage": twilio_usage,
            "_get_auth_session": Mock(return_value={"username": "operator"}),
            "_is_admin_user": self.is_admin,
            "_send_smtp_email": self.send_email,
            "_append_audit_event": self.audit,
            "SMTP_DEFAULT_FROM": "portal@example.com",
            "MOBILE_JABBER_EMAIL_FROM": "",
            "logger": Mock(),
        }
        module = ast.fix_missing_locations(ast.Module(body=[self.route_node], type_ignores=[]))
        exec(compile(module, "main.py", "exec"), self.scope)
        self.report = {
            "account_sid": ACCOUNT_SID,
            "account_name": "Test Account",
            "start_time": "2026-11-11T15:00:00Z",
            "end_time": "2026-11-11T17:00:00Z",
            "complete": True,
            "pages_read": 1,
            "error": "",
            "rows": [{
                "account_sid": ACCOUNT_SID,
                "date_sent": "2026-11-11T16:00:00+00:00",
                "to": "+12125550101",
                "error_code": 30003,
                "status": "undelivered",
                "from": "+12125550100",
                "message_sid": "SM" + "1" * 32,
                "body": "must not be attached",
            }],
        }

    def send(self, recipient="operator@example.com"):
        return self.scope["twilio_error_report_email_route"](
            SimpleNamespace(), recipient, json.dumps(self.report)
        )

    def test_sends_safe_csv_attachment_and_audits_success(self):
        response = self.send()

        self.assertEqual(response.status_code, 200)
        self.send_email.assert_called_once()
        arguments = self.send_email.call_args.kwargs
        self.assertEqual(arguments["recipients"], ["operator@example.com"])
        filename, attachment, mime_type = arguments["attachments"][0]
        self.assertEqual(filename, f"twilio_sms_error_report_{ACCOUNT_SID}.csv")
        self.assertEqual(mime_type, "text/csv")
        self.assertIn(b"Destination", attachment)
        self.assertNotIn(b"must not be attached", attachment)
        self.audit.assert_called_once()

    def test_rejects_bad_recipient_and_cross_account_rows(self):
        self.assertEqual(self.send("bad-address").status_code, 422)
        self.send_email.assert_not_called()

        self.report["rows"][0]["account_sid"] = ROOT_SID
        self.assertEqual(self.send().status_code, 422)
        self.send_email.assert_not_called()

    def test_requires_admin_authentication(self):
        self.is_admin.return_value = False

        self.assertEqual(self.send().status_code, 403)
        self.send_email.assert_not_called()

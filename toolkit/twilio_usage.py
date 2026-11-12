import datetime
import concurrent.futures
import csv
import email.utils
import io
import re
from urllib.parse import urljoin, urlsplit

import requests


_ACCOUNT_SID_RE = re.compile(r"AC[0-9a-fA-F]{32}")
_COUNT_RE = re.compile(r"[0-9]+")
MESSAGE_ERROR_CODE_MIN = 10_000
MESSAGE_ERROR_CODE_MAX = 99_999
OUTBOUND_DIRECTIONS = frozenset({"outbound-api", "outbound-call", "outbound-reply"})
MESSAGE_ERROR_PAGE_SIZE = 100
MESSAGE_ERROR_MAX_PAGES = 100


class TwilioUsageError(ValueError):
    pass


def _validated_date(value, field_name):
    if not isinstance(value, str):
        raise TwilioUsageError(f"{field_name} must be a YYYY-MM-DD date.")
    try:
        parsed = datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise TwilioUsageError(f"{field_name} must be a YYYY-MM-DD date.") from exc
    if parsed.isoformat() != value:
        raise TwilioUsageError(f"{field_name} must be a YYYY-MM-DD date.")
    return parsed


def validate_date_range(start_date, end_date):
    start = _validated_date(start_date, "Start date")
    end = _validated_date(end_date, "End date")
    if start > end:
        raise TwilioUsageError("Start date must be on or before end date.")
    return start.isoformat(), end.isoformat()


def _validated_datetime(value, field_name):
    if not isinstance(value, str) or not value.strip():
        raise TwilioUsageError(f"{field_name} must be a timezone-aware date and time.")
    try:
        parsed = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise TwilioUsageError(f"{field_name} must be a timezone-aware date and time.") from exc
    if parsed.tzinfo is None:
        raise TwilioUsageError(f"{field_name} must include a timezone.")
    return parsed.astimezone(datetime.timezone.utc)


def validate_datetime_range(start_time, end_time):
    start = _validated_datetime(start_time, "Start time")
    end = _validated_datetime(end_time, "End time")
    if start > end:
        raise TwilioUsageError("Start time must be on or before end time.")
    return start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z")


def discover_twilio_accounts(roots, root_errors, account_lister):
    root_by_sid = {root["sid"]: root for root in roots}
    accounts_by_sid = {}
    errors = [{
        "account_name": str(item.get("account_name", "Twilio account")),
        "account_sid": str(item.get("account_sid", "")),
        "error": "Account credentials are incomplete.",
    } for item in root_errors]

    def discover(root):
        try:
            return root, account_lister(root)
        except Exception:
            return root, {"ok": False, "status": "Account discovery failed", "accounts": []}

    if roots:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(roots))) as executor:
            futures = [executor.submit(discover, root) for root in roots]
            for future in concurrent.futures.as_completed(futures):
                root, result = future.result()
                if not isinstance(result, dict) or not result.get("ok"):
                    status = str((result or {}).get("status", "")) if isinstance(result, dict) else ""
                    match = re.search(r"HTTP [0-9]{3}", status)
                    errors.append({
                        "account_name": root["name"],
                        "account_sid": root["sid"],
                        "error": "Account discovery failed" + (" (" + match.group() + ")" if match else "."),
                    })
                    continue
                for account in result.get("accounts", []) or []:
                    account_sid = str(account.get("sid", "") or "").strip()
                    if not account_sid:
                        continue
                    direct_root = root_by_sid.get(account_sid)
                    auth_root = direct_root or root
                    if direct_root:
                        account_name = direct_root["name"]
                        account_type = "Root Account"
                        root_sid = direct_root["sid"]
                        root_name = direct_root["name"]
                    else:
                        account_name = str(account.get("friendly_name", "") or account_sid)
                        account_type = str(account.get("account_type", "Subaccount"))
                        root_sid = root["sid"]
                        root_name = root["name"]
                    accounts_by_sid[account_sid] = {
                        "sid": account_sid,
                        "account_name": account_name,
                        "account_type": account_type,
                        "root_account_sid": root_sid,
                        "root_account_name": root_name,
                        "auth_sid": auth_root["sid"],
                        "auth_token": auth_root["auth_token"],
                    }
    accounts = sorted(accounts_by_sid.values(), key=lambda row: (0 if row["account_type"] == "Root Account" else 1, row["account_name"].lower(), row["sid"]))
    return accounts, errors


def _message_page_url(account_sid, next_uri=""):
    base = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    if not next_uri:
        return base
    url = urljoin("https://api.twilio.com", next_uri)
    parsed = urlsplit(url)
    expected_path = urlsplit(base).path
    if parsed.scheme != "https" or parsed.netloc != "api.twilio.com" or parsed.path != expected_path or parsed.fragment:
        raise TwilioUsageError("Twilio returned an invalid or different-account message page link.")
    return url


def search_outbound_message_errors(account, start_time, end_time, next_uri="", pages_read=0, page_limit=None):
    start_iso, end_iso = validate_datetime_range(start_time, end_time)
    account_sid = str(account.get("sid", "") or "").strip()
    auth_sid = str(account.get("auth_sid", "") or "").strip()
    auth_token = str(account.get("auth_token", "") or "").strip()
    if not _ACCOUNT_SID_RE.fullmatch(account_sid) or not _ACCOUNT_SID_RE.fullmatch(auth_sid) or not auth_token:
        raise TwilioUsageError("Selected Twilio account authentication is not configured.")

    start = _validated_datetime(start_iso, "Start time")
    end = _validated_datetime(end_iso, "End time")
    try:
        pages_read = int(pages_read)
    except (TypeError, ValueError) as exc:
        raise TwilioUsageError("Message search cursor is invalid.") from exc
    if pages_read < 0 or pages_read > MESSAGE_ERROR_MAX_PAGES:
        raise TwilioUsageError("Message search cursor is invalid.")
    if not isinstance(next_uri, str):
        raise TwilioUsageError("Message search cursor is invalid.")
    if page_limit is not None and (not isinstance(page_limit, int) or page_limit < 1):
        raise TwilioUsageError("Message search page limit is invalid.")
    next_uri = next_uri.strip()
    seen_urls = set()
    seen_message_sids = set()
    rows = []
    error = ""
    request_pages = 0

    while True:
        if pages_read >= MESSAGE_ERROR_MAX_PAGES:
            error = f"Page limit reached after {pages_read} pages; results may be incomplete."
            break
        if page_limit is not None and request_pages >= page_limit:
            break
        try:
            url = _message_page_url(account_sid, next_uri)
            if url in seen_urls:
                raise TwilioUsageError("Twilio repeated a message page link.")
            seen_urls.add(url)
            response = requests.get(
                url,
                params=None if next_uri else {
                    "DateSent>=": start_iso,
                    "DateSent<=": end_iso,
                    "PageSize": MESSAGE_ERROR_PAGE_SIZE,
                },
                auth=(auth_sid, auth_token),
                timeout=30,
                allow_redirects=False,
            )
            if response.status_code != 200:
                raise TwilioUsageError(f"Twilio message search failed (HTTP {response.status_code}).")
            payload = response.json()
            messages = payload.get("messages") if isinstance(payload, dict) else None
            if not isinstance(messages, list) or "next_page_uri" not in payload:
                raise TwilioUsageError("Twilio returned an invalid message-page response.")
            pages_read += 1
            request_pages += 1
            for message in messages:
                if not isinstance(message, dict) or message.get("account_sid") != account_sid:
                    raise TwilioUsageError("Twilio returned a different-account message.")
                if message.get("direction") not in OUTBOUND_DIRECTIONS:
                    continue
                try:
                    error_code = int(message.get("error_code"))
                except (TypeError, ValueError):
                    continue
                if error_code == 0 or not MESSAGE_ERROR_CODE_MIN <= error_code <= MESSAGE_ERROR_CODE_MAX:
                    continue
                sid = str(message.get("sid", "") or "").strip()
                destination = str(message.get("to", "") or "").strip()
                date_sent = message.get("date_sent")
                if not sid or sid in seen_message_sids or not destination or not date_sent:
                    continue
                try:
                    sent_at = email.utils.parsedate_to_datetime(date_sent)
                    if sent_at.tzinfo is None:
                        continue
                    sent_at = sent_at.astimezone(datetime.timezone.utc)
                except (TypeError, ValueError, OverflowError):
                    continue
                if not start <= sent_at <= end:
                    continue
                seen_message_sids.add(sid)
                rows.append({
                    "account_sid": account_sid,
                    "account_name": str(account.get("account_name", account_sid)),
                    "message_sid": sid,
                    "date_sent": sent_at.isoformat(),
                    "from": str(message.get("from", "") or ""),
                    "to": destination,
                    "status": str(message.get("status", "") or ""),
                    "error_code": error_code,
                })
            next_uri = str(payload.get("next_page_uri", "") or "").strip()
            if not next_uri:
                break
            if _message_page_url(account_sid, next_uri) == url:
                raise TwilioUsageError("Twilio repeated a message page link.")
        except (requests.RequestException, TwilioUsageError, ValueError, TypeError) as exc:
            error = str(exc) if isinstance(exc, TwilioUsageError) else "Twilio message search could not complete."
            break

    rows.sort(key=lambda row: (row["date_sent"], row["to"], row["error_code"]), reverse=True)
    return {
        "account_sid": account_sid,
        "account_name": str(account.get("account_name", account_sid)),
        "start_time": start_iso,
        "end_time": end_iso,
        "rows": rows,
        "pages_read": pages_read,
        "next_uri": next_uri,
        "complete": not error and not next_uri,
        "error": error,
    }


def build_outbound_message_errors_csv(report):
    if not isinstance(report, dict) or not isinstance(report.get("rows"), list):
        raise TwilioUsageError("Error report rows are invalid.")

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("Account", "Sent (UTC)", "Destination", "Error Code", "Status", "From", "Message SID", "Search Complete", "Pages Read", "Coverage Warning"))

    def safe_cell(value):
        text = "" if value is None else str(value)
        if text.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    for row in report["rows"]:
        if not isinstance(row, dict):
            raise TwilioUsageError("Error report contains an invalid row.")
        writer.writerow(safe_cell(value) for value in (
            report.get("account_name", ""),
            row.get("date_sent", ""),
            row.get("to", ""),
            row.get("error_code", ""),
            row.get("status", ""),
            row.get("from", ""),
            row.get("message_sid", ""),
            report.get("complete", False),
            report.get("pages_read", 0),
            report.get("error", ""),
        ))

    return output.getvalue().encode("utf-8")


def read_outbound_sms_usage(account_sid, auth_sid, auth_token, start_date, end_date):
    if not isinstance(account_sid, str) or not _ACCOUNT_SID_RE.fullmatch(account_sid):
        raise TwilioUsageError("Invalid Twilio account SID.")
    if not isinstance(auth_sid, str) or not _ACCOUNT_SID_RE.fullmatch(auth_sid) or not isinstance(auth_token, str) or not auth_token.strip():
        raise TwilioUsageError("Twilio account authentication is not configured.")

    start_date, end_date = validate_date_range(start_date, end_date)

    url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Usage/Records.json"
    try:
        response = requests.get(
            url,
            params={"Category": "sms-outbound", "StartDate": start_date, "EndDate": end_date},
            auth=(auth_sid, auth_token),
            timeout=20,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise TwilioUsageError("Twilio outbound SMS usage request could not complete.") from exc

    if response.status_code != 200:
        raise TwilioUsageError(f"Twilio outbound SMS usage query failed (HTTP {response.status_code}).")

    try:
        payload = response.json()
        records = payload.get("usage_records") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            raise ValueError("Invalid usage record list.")
        matching = [record for record in records if isinstance(record, dict) and record.get("category") == "sms-outbound"]
        if len(matching) != 1:
            raise ValueError("Expected one outbound SMS usage record.")
        record = matching[0]
        if record.get("account_sid") != account_sid:
            raise ValueError("Usage record belongs to a different account.")
        raw_count = record.get("count")
        if not isinstance(raw_count, (str, int)) or not _COUNT_RE.fullmatch(str(raw_count)):
            raise ValueError("Outbound SMS count is missing or invalid.")
        return {
            "count": int(raw_count),
            "count_unit": str(record.get("count_unit", "") or ""),
            "as_of": str(record.get("as_of", "") or ""),
            "start_date": start_date,
            "end_date": end_date,
        }
    except (TypeError, ValueError, AttributeError) as exc:
        raise TwilioUsageError("Twilio returned incomplete or invalid outbound SMS usage data.") from exc


def build_outbound_sms_usage_report(roots, root_errors, account_lister, start_date, end_date, usage_reader=None):
    start_date, end_date = validate_date_range(start_date, end_date)
    if not roots and not root_errors:
        raise TwilioUsageError("No Twilio account credentials are configured.")
    accounts, errors = discover_twilio_accounts(roots, root_errors, account_lister)
    accounts_by_sid = {account["sid"]: account for account in accounts}

    read_usage = usage_reader or read_outbound_sms_usage

    def read_account(account):
        row = {
            "account_sid": account["sid"],
            "account_name": account["account_name"],
            "account_type": account["account_type"],
            "root_account_sid": account["root_account_sid"],
            "root_account_name": account["root_account_name"],
            "count": None,
            "count_unit": "messages",
            "as_of": "",
            "status": "Lookup Failed",
        }
        try:
            usage = read_usage(account["sid"], account["auth_sid"], account["auth_token"], start_date, end_date)
            row.update({"count": usage["count"], "count_unit": usage["count_unit"], "as_of": usage["as_of"], "status": "Loaded"})
            return row, ""
        except TwilioUsageError as exc:
            return row, str(exc)
        except Exception:
            return row, "Outbound SMS usage lookup failed."

    rows = []
    if accounts_by_sid:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(accounts_by_sid))) as executor:
            futures = [executor.submit(read_account, account) for account in accounts_by_sid.values()]
            for future in concurrent.futures.as_completed(futures):
                row, error = future.result()
                rows.append(row)
                if error:
                    errors.append({"account_name": row["account_name"], "account_sid": row["account_sid"], "error": error})

    rows.sort(key=lambda row: (0 if row["account_type"] == "Root Account" else 1, row["account_name"].lower(), row["account_sid"]))
    total_count = sum(row["count"] for row in rows if row["count"] is not None)
    return {
        "start_date": start_date,
        "end_date": end_date,
        "rows": rows,
        "errors": errors,
        "total_count": total_count,
        "coverage_complete": not errors and len(rows) == len(accounts_by_sid),
        "account_count": len(rows),
        "discovered_account_count": len(accounts_by_sid),
    }

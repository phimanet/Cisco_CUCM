import datetime
import json
import os
import re
import tempfile
import time
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urljoin, urlsplit
from uuid import uuid4

import requests


MAX_MESSAGE_PAGES = 100
OUTBOUND_DIRECTIONS = {"outbound-api", "outbound-call", "outbound-reply"}


def sms_numbers(inventory, account_sid):
    numbers = set()
    excluded = 0
    for item in inventory:
        if not isinstance(item, dict) or item.get("account_sid") != account_sid:
            raise ValueError("AMIEWeb inventory contains an invalid or different-account record.")
        capabilities = item.get("capabilities")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("sms"), bool):
            raise ValueError("SMS capability is unavailable in the AMIEWeb number inventory.")
        if not capabilities["sms"]:
            excluded += 1
            continue
        number = str(item.get("phone_number", "") or "").strip()
        if not re.fullmatch(r"\+[1-9][0-9]{7,14}", number):
            raise ValueError("AMIEWeb inventory contains an invalid SMS number.")
        numbers.add(number)
    return sorted(numbers), excluded


def _message_url(account_sid, number, next_uri):
    base = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
    if not next_uri:
        return base
    url = urljoin("https://api.twilio.com", next_uri)
    parsed = urlsplit(url)
    expected_path = urlsplit(base).path
    query = parse_qs(parsed.query)
    if parsed.scheme != "https" or parsed.netloc != "api.twilio.com" or parsed.path != expected_path or parsed.fragment or query.get("From") != [number]:
        raise ValueError("Twilio returned an invalid or different-account message-page link.")
    return url


def _timestamp(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Outbound message timestamp was not returned.")
    try:
        moment = parsedate_to_datetime(value)
    except (ValueError, TypeError):
        try:
            moment = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Outbound message timestamp is invalid.") from exc
    if moment.tzinfo is None:
        raise ValueError("Outbound message timestamp has no timezone.")
    return moment.astimezone(datetime.timezone.utc).isoformat()


def read_latest_outbound_page(account_sid, auth_sid, auth_token, number, next_uri="", pages_read=0):
    if not re.fullmatch(r"AC[0-9a-fA-F]{32}", account_sid or "") or not auth_sid or not auth_token:
        raise ValueError("AMIEWeb Twilio credentials are not configured.")
    if not re.fullmatch(r"\+[1-9][0-9]{7,14}", number or ""):
        raise ValueError("Invalid SMS sender number.")
    if pages_read >= MAX_MESSAGE_PAGES:
        return {"status": "Lookup Failed", "error": "Message-page limit reached; outbound history is incomplete."}
    url = _message_url(account_sid, number, next_uri)
    try:
        response = requests.get(
            url, params=None if next_uri else {"From": number, "PageSize": 1},
            auth=(auth_sid, auth_token), timeout=20, allow_redirects=False,
        )
    except requests.RequestException:
        return {"status": "Retry", "error": "Twilio message request could not complete.", "retry_after": 2}
    if response.status_code in (401, 403):
        return {"status": "Account Error", "error": f"Twilio authorization failed (HTTP {response.status_code})."}
    if response.status_code == 429 or response.status_code >= 500:
        try:
            delay = min(60, max(1, int(response.headers.get("Retry-After", "2"))))
        except (TypeError, ValueError):
            delay = 2
        return {"status": "Retry", "error": f"Twilio message read failed (HTTP {response.status_code}).", "retry_after": delay}
    if response.status_code != 200:
        return {"status": "Lookup Failed", "error": f"Twilio message read failed (HTTP {response.status_code})."}
    try:
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list) or "next_page_uri" not in payload:
            raise ValueError("Twilio returned an invalid message-list response.")
        for message in payload["messages"]:
            if not isinstance(message, dict) or message.get("account_sid") != account_sid or message.get("from") != number:
                raise ValueError("Twilio returned a different-account or different-sender message.")
            direction = message.get("direction")
            if direction == "inbound":
                continue
            if direction not in OUTBOUND_DIRECTIONS:
                raise ValueError("Twilio returned an unknown message direction.")
            source = "date_sent" if message.get("date_sent") else "date_created"
            return {"status": "Found", "latest_outbound_at": _timestamp(message.get(source)), "timestamp_source": source}
        next_page = payload["next_page_uri"]
        if next_page:
            if not isinstance(next_page, str) or not payload["messages"]:
                raise ValueError("Twilio message pagination is invalid.")
            validated = _message_url(account_sid, number, next_page)
            if validated == url:
                raise ValueError("Twilio message pagination repeated the current page.")
            return {"status": "Continue", "next_uri": next_page, "pages_read": pages_read + 1}
        return {"status": "No outbound log available", "latest_outbound_at": "", "timestamp_source": ""}
    except (ValueError, TypeError):
        return {"status": "Lookup Failed", "error": "Twilio returned incomplete or invalid message history."}


def create_job(inventory, account_sid, account_name):
    numbers, excluded = sms_numbers(inventory, account_sid)
    friendly_names = {str(item.get("phone_number", "") or "").strip(): str(item.get("friendly_name", "") or "").strip() for item in inventory}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "schema_version": 1, "job_id": uuid4().hex, "account_sid": account_sid,
        "account_name": account_name, "created_at": now, "updated_at": now,
        "status": "paused" if numbers else "completed", "cursor": 0,
        "rows": [{"phone_number": number, "friendly_name": friendly_names.get(number, ""), "latest_outbound_at": "", "timestamp_source": "", "status": "Pending", "error": "", "checked_at": ""} for number in numbers],
        "next_uri": "", "pages_read": 0, "retries": 0, "retry_not_before": 0,
        "excluded_non_sms": excluded, "error": "",
        "scope_note": "SMS-capable Incoming Phone Number (PN) inventory only; Hosted Number (HN) inventory is not included. Outbound SMS/MMS log timestamps are not delivery confirmation. Twilio retention/deletion limits apply; no outbound log does not establish inactivity. DateSent is used where available; otherwise the returned record's creation time is shown.",
    }


def advance_job(state, account_sid, auth_sid, auth_token):
    if state.get("account_sid") != account_sid:
        raise ValueError("Saved recent-log job belongs to a different Twilio account.")
    if state["status"] in ("completed", "failed"):
        return
    if time.time() < state.get("retry_not_before", 0):
        return
    row = state["rows"][state["cursor"]]
    result = read_latest_outbound_page(account_sid, auth_sid, auth_token, row["phone_number"], state["next_uri"], state["pages_read"])
    status = result["status"]
    state["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if status == "Account Error":
        state.update(status="failed", error=result["error"])
        return
    if status == "Retry":
        state["retries"] += 1
        if state["retries"] <= 3:
            state["retry_not_before"] = time.time() + result["retry_after"]
            return
        result = {"status": "Lookup Failed", "error": "Twilio message lookup still unavailable after retries."}
        status = result["status"]
    state["retry_not_before"] = 0
    state["retries"] = 0
    if status == "Continue":
        state["next_uri"] = result["next_uri"]
        state["pages_read"] = result["pages_read"]
        return
    row.update({
        "status": status, "latest_outbound_at": result.get("latest_outbound_at", ""),
        "timestamp_source": result.get("timestamp_source", ""), "error": result.get("error", ""),
        "checked_at": state["updated_at"],
    })
    state["cursor"] += 1
    state["next_uri"] = ""
    state["pages_read"] = 0
    if state["cursor"] == len(state["rows"]):
        state["status"] = "completed"


def state_path(root, account_sid, kind):
    if not re.fullmatch(r"AC[0-9a-fA-F]{32}", account_sid or "") or kind not in ("job", "report"):
        raise ValueError("Invalid AMIEWeb recent-log storage key.")
    return os.path.join(root, account_sid + "." + kind + ".json")


def save_state(root, state, kind="job"):
    path = state_path(root, state["account_sid"], kind)
    os.makedirs(root, exist_ok=True)
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, suffix=".tmp", delete=False) as handle:
            temp_path = handle.name
            json.dump(state, handle, ensure_ascii=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = ""
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def load_state(root, account_sid, kind="job"):
    with open(state_path(root, account_sid, kind), "r", encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict) or state.get("schema_version") != 1 or state.get("account_sid") != account_sid or not isinstance(state.get("rows"), list) or state.get("status") not in ("paused", "completed", "failed"):
        raise ValueError("Saved recent-log state is invalid or belongs to another account.")
    return state


def public_state(state):
    rows = state["rows"]
    return {
        "job_id": state["job_id"], "account_name": state["account_name"], "status": state["status"],
        "created_at": state["created_at"], "updated_at": state["updated_at"], "completed": state["cursor"],
        "total": len(rows), "rows": rows, "excluded_non_sms": state["excluded_non_sms"],
        "found": sum(row["status"] == "Found" for row in rows),
        "no_history": sum(row["status"] == "No outbound log available" for row in rows),
        "failed": sum(row["status"] == "Lookup Failed" for row in rows),
        "retry_after": max(0, state["retry_not_before"] - time.time()),
        "error": state["error"], "scope_note": state["scope_note"],
    }
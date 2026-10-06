import datetime
import json
import os
import re
import tempfile
import time
from uuid import uuid4

from toolkit import twilio_recent_logs


ACTIVE_STATUSES = {"queued", "running", "paused"}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def configured_sids(roots):
    return sorted({root["sid"] for root in roots})


def create_job(roots, operator):
    if not roots or any(not re.fullmatch(r"AC[0-9a-fA-F]{32}", root.get("sid", "")) for root in roots):
        raise ValueError("Complete Twilio inventory root credentials are required.")
    now = _now()
    return {
        "schema_version": 1, "job_id": uuid4().hex, "operator": operator, "status": "queued",
        "root_sids": configured_sids(roots), "created_at": now, "updated_at": now,
        "inventory_ready": False, "rows": [], "accounts": [], "inventory_failures": [],
        "account_errors": {}, "excluded_non_sms": 0, "cursor": 0, "next_uri": "",
        "pages_read": 0, "retries": 0, "retry_not_before": 0, "error": "",
        "scope_note": "Read-only latest retained outbound SMS/MMS logs for SMS-capable Incoming Phone Numbers (PN), across configured roots and accessible subaccounts. Hosted Numbers (HN) are not included. No outbound log does not establish inactivity. Twilio retention/deletion limits apply; timestamps are not proof of delivery. DateSent is used when returned, otherwise DateCreated is explicitly identified.",
    }


def initialize_inventory(state, inventory):
    rows = inventory.get("rows")
    if not isinstance(rows, list) or not isinstance(inventory.get("failures"), list):
        raise ValueError("All-account inventory response is incomplete.")
    unique = {}
    excluded = 0
    for item in rows:
        if not isinstance(item, dict):
            raise ValueError("All-account inventory contains an invalid number record.")
        if "SMS" not in str(item.get("capabilities", "")).split(", "):
            excluded += 1
            continue
        account_sid = item.get("account_sid", "")
        root_sid = item.get("root_account_sid", "")
        number = str(item.get("phone_number", "") or "").strip()
        if not re.fullmatch(r"AC[0-9a-fA-F]{32}", account_sid) or root_sid not in state["root_sids"] or not re.fullmatch(r"\+[1-9][0-9]{7,14}", number):
            raise ValueError("Inventory contains an invalid or out-of-scope SMS account/number.")
        key = (account_sid, number)
        unique[key] = {
            "account_sid": account_sid, "account_name": str(item.get("account_name", "") or account_sid),
            "root_account_sid": root_sid, "root_account_name": str(item.get("root_account_name", "") or ""),
            "phone_number": number, "friendly_name": str(item.get("friendly_name", "") or ""),
            "latest_outbound_at": "", "timestamp_source": "", "status": "Pending", "error": "", "checked_at": "",
        }
    state["rows"] = [unique[key] for key in sorted(unique)]
    state["accounts"] = [
        {"account_sid": str(item.get("sid", "")), "account_name": str(item.get("friendly_name", "")),
         "root_account_sid": str(item.get("root_account_sid", ""))}
        for item in inventory.get("accounts", [])
    ]
    state["inventory_failures"] = []
    for item in inventory["failures"]:
        http_status = re.search(r"HTTP [0-9]{3}", str(item.get("error", "")))
        state["inventory_failures"].append({
            "account_name": str(item.get("account_name", "")), "account_sid": str(item.get("account_sid", "")),
            "error": "Account discovery/SMS inventory lookup failed" + (" (" + http_status.group() + ")" if http_status else "."),
        })
    state["excluded_non_sms"] = excluded
    state["inventory_ready"] = True
    state["updated_at"] = _now()
    if state["rows"]:
        state["status"] = "running"
    else:
        state["status"] = "failed" if state["inventory_failures"] else "completed"
        if state["status"] == "failed":
            state["error"] = "No SMS inventory could be loaded; account discovery/inventory failed."


def advance_job(state, roots):
    if state["root_sids"] != configured_sids(roots):
        raise ValueError("Configured Twilio roots changed; submit a new all-account job.")
    if state["status"] != "running" or time.time() < state["retry_not_before"]:
        return
    row = state["rows"][state["cursor"]]
    root_by_sid = {root["sid"]: root for root in roots}
    root = root_by_sid.get(row["account_sid"]) or root_by_sid.get(row["root_account_sid"])
    if not root or not root.get("auth_token"):
        raise ValueError("The queued account's credential root is no longer configured.")
    result = twilio_recent_logs.read_latest_outbound_page(
        row["account_sid"], root["sid"], root["auth_token"], row["phone_number"], state["next_uri"], state["pages_read"],
    )
    state["updated_at"] = _now()
    status = result["status"]
    if status == "Retry":
        state["retries"] += 1
        if state["retries"] <= 3:
            state["retry_not_before"] = time.time() + result["retry_after"]
            return
        status = "Lookup Failed"
        result = {"status": status, "error": "Twilio lookup unavailable after bounded retries."}
    state["retries"] = 0
    state["retry_not_before"] = 0
    if status == "Continue":
        state["next_uri"] = result["next_uri"]
        state["pages_read"] = result["pages_read"]
        return
    if status == "Account Error":
        account_sid = row["account_sid"]
        state["account_errors"][account_sid] = result["error"]
        while state["cursor"] < len(state["rows"]) and state["rows"][state["cursor"]]["account_sid"] == account_sid:
            failed_row = state["rows"][state["cursor"]]
            failed_row.update(status="Lookup Failed", error=result["error"], checked_at=state["updated_at"])
            state["cursor"] += 1
    else:
        row.update({"status": status, "latest_outbound_at": result.get("latest_outbound_at", ""),
                    "timestamp_source": result.get("timestamp_source", ""), "error": result.get("error", ""), "checked_at": state["updated_at"]})
        state["cursor"] += 1
    state["next_uri"] = ""
    state["pages_read"] = 0
    if state["cursor"] == len(state["rows"]):
        if any(item["status"] in {"Found", "No outbound log available"} for item in state["rows"]):
            state["status"] = "completed"
        else:
            state["status"] = "failed"
            state["error"] = "All message lookups failed; the previous completed report is retained."


def save_state(root, state, kind="job"):
    if kind not in ("job", "report"):
        raise ValueError("Invalid all-account state kind.")
    os.makedirs(root, exist_ok=True)
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, suffix=".tmp", delete=False) as handle:
            temp_path = handle.name
            json.dump(state, handle, ensure_ascii=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, os.path.join(root, kind + ".json"))
        temp_path = ""
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def load_state(root, kind="job"):
    if kind not in ("job", "report"):
        raise ValueError("Invalid all-account state kind.")
    with open(os.path.join(root, kind + ".json"), "r", encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict) or state.get("schema_version") != 1 or not state.get("job_id") or state.get("status") not in ACTIVE_STATUSES | {"completed", "failed", "cancelled"} or not isinstance(state.get("rows"), list) or not isinstance(state.get("root_sids"), list):
        raise ValueError("All-account recent-log state is invalid and was not overwritten.")
    return state


def public_state(state, include_rows=True):
    rows = state["rows"]
    result = {
        "job_id": state["job_id"], "status": state["status"], "created_at": state["created_at"],
        "updated_at": state["updated_at"], "inventory_ready": state["inventory_ready"],
        "completed": state["cursor"], "total": len(rows), "account_count": len(state["accounts"]),
        "found": sum(row["status"] == "Found" for row in rows),
        "no_history": sum(row["status"] == "No outbound log available" for row in rows),
        "failed": sum(row["status"] == "Lookup Failed" for row in rows),
        "inventory_failures": state["inventory_failures"], "excluded_non_sms": state["excluded_non_sms"],
        "retry_after": max(0, state["retry_not_before"] - time.time()), "error": state["error"],
        "scope_note": state["scope_note"],
    }
    if include_rows:
        result["rows"] = rows
    return result
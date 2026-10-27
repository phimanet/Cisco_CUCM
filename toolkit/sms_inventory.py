import copy
import datetime
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
from urllib.parse import urljoin, urlsplit

import requests


CACHE_TTL_SECONDS = 8 * 60 * 60
_INVENTORY_FIELDS = ("provider", "environment", "account", "phone_number", "friendly_name", "description", "connection", "record_id")
_CACHE_LOCK = threading.RLock()


def normalized_number(value):
    raw = str(value or "").strip()
    if not raw or not re.fullmatch(r"\+?[0-9(). -]+", raw):
        return ""
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits if 3 <= len(digits) <= 15 else ""


class InventoryCache:
    def __init__(self, root):
        self.root = Path(root)
        self.path = self.root / "inventory.json"

    def _read(self):
        try:
            with self.path.open(encoding="utf-8") as handle:
                cache = json.load(handle)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise ValueError("Saved SMS inventory is unreadable; preserve and inspect the cache before refreshing.") from exc
        if not isinstance(cache, dict) or cache.get("version") != 1 or not isinstance(cache.get("rows"), list) or not isinstance(cache.get("scope_key"), str) or cache.get("failures") != [] or cache.get("status") != "Complete within stated scope":
            raise ValueError("Saved SMS inventory has invalid metadata; it was not overwritten.")
        if any(not isinstance(row, dict) or set(row) != set(_INVENTORY_FIELDS) or row.get("provider") not in {"Twilio", "Aerialink"} or not normalized_number(row.get("phone_number")) or any(not isinstance(value, str) for value in row.values()) for row in cache["rows"]):
            raise ValueError("Saved SMS inventory has invalid rows; it was not used or overwritten.")
        return cache

    def _save(self, cache):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(dir=self.root, suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(cache, handle, ensure_ascii=True)
                handle.flush()
                os.fsync(handle.fileno())
            for attempt in range(3):
                try:
                    os.replace(temporary, self.path)
                    break
                except PermissionError:
                    if os.name != "nt" or attempt == 2:
                        raise
                    time.sleep(0.05 * (attempt + 1))
            if os.name != "nt":
                directory = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def get(self, scope_key, extract, *, force_refresh=False, at=None):
        with _CACHE_LOCK:
            current = at or datetime.datetime.now(datetime.timezone.utc)
            cached = self._read()
            if cached:
                try:
                    fetched = datetime.datetime.fromisoformat(cached["fetched_at"])
                    age = (current - fetched).total_seconds()
                    expires = datetime.datetime.fromisoformat(cached["expires_at"])
                    if (expires - fetched).total_seconds() != CACHE_TTL_SECONDS:
                        raise ValueError("Invalid SMS inventory expiry.")
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError("Saved SMS inventory has an invalid timestamp; it was not overwritten.") from exc
                if age < 0:
                    raise ValueError("Saved SMS inventory is future-dated; it was not used or overwritten.")
                if not force_refresh and cached["scope_key"] == scope_key and age < CACHE_TTL_SECONDS:
                    return {**copy.deepcopy(cached), "cache_hit": True}
            result = extract()
            if not isinstance(result, dict) or not result.get("ok") or not isinstance(result.get("rows"), list):
                raise ValueError("SMS inventory refresh failed; the prior saved inventory was retained.")
            rows = []
            for row in result["rows"]:
                if not isinstance(row, dict) or not normalized_number(row.get("phone_number")) or row.get("provider") not in {"Twilio", "Aerialink"}:
                    raise ValueError("SMS inventory returned invalid rows; the prior saved inventory was retained.")
                rows.append({key: str(row.get(key) or "") for key in _INVENTORY_FIELDS})
            fetched = datetime.datetime.fromisoformat(result.get("fetched_at") or current.isoformat())
            completed = at or datetime.datetime.now(datetime.timezone.utc)
            if not 0 <= (completed - fetched).total_seconds() < CACHE_TTL_SECONDS:
                raise ValueError("SMS inventory refresh returned an invalid timestamp.")
            failures = result.get("failures", [])
            if not isinstance(failures, list):
                raise ValueError("SMS inventory returned invalid coverage information.")
            report = {"version": 1, "scope_key": scope_key, "rows": rows, "count": len(rows),
                "fetched_at": fetched.isoformat(), "expires_at": (fetched + datetime.timedelta(seconds=CACHE_TTL_SECONDS)).isoformat(),
                "status": "Partial" if failures else "Complete within stated scope", "failures": [str(value) for value in failures],
                "scope": str(result.get("scope") or ""), "cache_hit": False}
            if not failures:
                self._save({key: value for key, value in report.items() if key != "cache_hit"})
            return report


def annotate_review(snapshots, report):
    report = report or {}
    index = {}
    for row in report.get("rows", []):
        number = normalized_number(row.get("phone_number"))
        if number:
            index.setdefault(number, []).append({key: str(row.get(key) or "") for key in ("provider", "environment", "account", "phone_number", "friendly_name", "connection")})
    complete = report.get("status") == "Complete within stated scope" and not report.get("failures")
    for snapshot in snapshots.values():
        checks, matches = [], []
        for extension in sorted({line["extension"] for line in snapshot.get("extensions", [])}):
            number = normalized_number(extension)
            found = index.get(number, []) if number else []
            status = "Not checked" if not number else "Yes" if found else "No" if complete else "Lookup Failed"
            checks.append({"extension": extension, "normalized_number": number, "status": status, "matches": found})
            for record in found:
                if record not in matches:
                    matches.append(record)
        statuses = {check["status"] for check in checks}
        snapshot["sms"] = "Yes" if "Yes" in statuses else "Lookup Failed" if "Lookup Failed" in statuses else "No" if statuses == {"No"} else "Not checked"
        snapshot["sms_checks"] = checks
        snapshot["sms_matches"] = matches
        for key in ("fetched_at", "expires_at", "status", "scope", "failures", "cache_hit"):
            snapshot["sms_inventory_" + key] = copy.deepcopy(report.get(key))
    return snapshots


def aerialink_numbers(base_url, lookup_path, username, password, get=None):
    if not username or not password:
        raise ValueError("Aerialink credentials are not configured.")
    get = get or requests.get
    first_url = base_url.rstrip("/") + "/" + lookup_path.lstrip("/")
    origin = urlsplit(first_url)
    if origin.scheme != "https" or not origin.hostname or origin.username or origin.password:
        raise ValueError("Aerialink inventory requires a configured HTTPS endpoint.")
    allowed_paths = {origin.path, origin.path.rstrip("s")}
    rows, seen_urls, seen_ids = [], set(), set()
    next_url = first_url
    total = pages = None
    for expected_page in range(1, 1001):
        target = urlsplit(next_url)
        if (target.scheme, target.netloc) != (origin.scheme, origin.netloc) or target.path not in allowed_paths or target.fragment:
            raise ValueError("Unsafe Aerialink pagination link was refused.")
        if next_url in seen_urls:
            raise ValueError("Repeated Aerialink pagination link was refused.")
        seen_urls.add(next_url)
        try:
            response = get(next_url, auth=(username, password), headers={"Accept": "application/json"},
                           verify=False, timeout=30, allow_redirects=False)
            if response.status_code != 200:
                raise ValueError(f"Aerialink inventory failed HTTP {response.status_code}.")
            payload = response.json()
        except requests.RequestException:
            raise ValueError("Aerialink inventory request failed; check connectivity and configuration.") from None
        except (TypeError, ValueError) as error:
            if isinstance(error, ValueError) and str(error).startswith("Aerialink inventory failed HTTP"):
                raise
            raise ValueError("Aerialink inventory returned invalid JSON.") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list) or not isinstance(payload.get("paging"), dict):
            raise ValueError("Aerialink inventory returned an unexpected collection.")
        batch, paging = payload["data"], payload["paging"]
        for key in ("totalRecords", "totalPages", "page", "pageSize", "pageCount"):
            if type(paging.get(key)) is not int or paging[key] < 0:
                raise ValueError("Aerialink inventory returned invalid pagination metadata.")
        if total is None:
            total, pages = paging["totalRecords"], paging["totalPages"]
        if (paging["totalRecords"], paging["totalPages"]) != (total, pages) or paging["page"] != expected_page:
            raise ValueError("Aerialink inventory changed or repeated a page; refresh again.")
        if paging["pageCount"] != len(batch) or not paging["pageSize"] or len(batch) > paging["pageSize"]:
            raise ValueError("Aerialink inventory page counts are inconsistent.")
        for record in batch:
            if not isinstance(record, dict):
                raise ValueError("Aerialink inventory returned an invalid record.")
            identity = str(record.get("codeGUID") or "").strip()
            number = str(record.get("number") or record.get("code") or "").strip()
            if not identity or identity in seen_ids or not number.lstrip("+").isdigit() or not 3 <= len(number.lstrip("+")) <= 15:
                raise ValueError("Aerialink inventory contains a repeated or invalid number record.")
            seen_ids.add(identity)
            rows.append({"provider": "Aerialink", "environment": "AMIEClassic",
                         "account": str(record.get("accountName") or ""), "phone_number": number,
                         "friendly_name": str(record.get("name") or ""), "description": "",
                         "connection": str(record.get("connectionName") or ""), "record_id": identity})
        following = paging.get("next")
        if following is not None and not isinstance(following, str):
            raise ValueError("Aerialink inventory returned an invalid next-page link.")
        if expected_page >= pages:
            if following or len(rows) != total:
                raise ValueError("Aerialink inventory is incomplete; reported totals do not match.")
            return rows
        if not following or not batch or len(rows) >= total:
            raise ValueError("Aerialink inventory ended before all reported pages were returned.")
        next_url = urljoin(next_url, following)
    raise ValueError("Aerialink inventory exceeded the page limit.")


def twilio_sms_rows(inventory):
    rows, seen = [], set()
    for record in inventory["rows"]:
        if "SMS" not in str(record.get("capabilities") or "").split(", "):
            continue
        identity = (record["account_sid"], record["phone_number"])
        if identity in seen:
            continue
        seen.add(identity)
        rows.append({"provider": "Twilio", "environment": record["account_name"],
                     "account": record["root_account_name"], "phone_number": record["phone_number"],
                     "friendly_name": record["friendly_name"], "description": "", "connection": "",
                     "record_id": record.get("phone_sid", "")})
    return rows
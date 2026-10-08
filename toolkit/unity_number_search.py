import hashlib
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import requests


class UnitySearchError(RuntimeError):
    pass


class UnityCountOnlyPage(UnitySearchError):
    def __init__(self, total):
        super().__init__("CUPI returned a positive collection count without records; inventory is not empty.")
        self.total = total


EXCLUDED = re.compile(r"password|passwd|credential|secret|token|pin(?:hash|digest|$)|certificate|authorizationcode|voicename|voicefile|streamfile|recording", re.I)
NUMBER_FIELD = re.compile(r"extension|dtmfaccessid|phone|dial|callback|contactnumber|transfernumber|callingnumber|callednumber|forwardingnumber", re.I)
UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
CACHE_TTL_SECONDS = 8 * 60 * 60
RETENTION = "Latest configuration cache, latest scan and latest completed lookup per Unity host only; not an archive. Cache expires after eight hours from the beginning of its load. External runtime data survives normal restarts and code pulls, not data deletion or older data/VM restores."
LIMITS = "Read-only CUPI configuration search, not deletion clearance. Recorded audio, messages, credentials, binary data, inaccessible/unadvertised resources, personal call-transfer rules, and external systems are not searched. Stored references do not prove an active call path; schedules, actions, disabled rules, and wildcard semantics require operator review."


def normalize_query(value):
    text = str(value or "").strip()
    if not re.fullmatch(r"[0-9+().\s-]+", text):
        raise ValueError("Enter a number or number fragment using digits and phone formatting only.")
    digits = re.sub(r"[^0-9]", "", text)
    if not 3 <= len(digits) <= 15:
        raise ValueError("Enter 3-15 digits.")
    return digits


def normalize_host(value):
    text = str(value or "").strip().lower()
    parsed = urlsplit(text if "://" in text else "https://" + text)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("A Unity HTTPS hostname is required.")
    return parsed.netloc


def scalar_fields(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key)
            if EXCLUDED.search(name):
                continue
            path = prefix + "." + name if prefix else name
            yield from scalar_fields(item, path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from scalar_fields(item, f"{prefix}[{index}]")
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield prefix, str(value)


def record_evidence(record, owner, resource):
    context = "; ".join(f"{key}={record[key]}" for key in (
        "TransferOptionType", "GreetingType", "TouchtoneKey", "Key", "Action",
        "AfterGreetingAction", "AfterMessageAction", "TargetConversation",
        "AfterGreetingTargetConversation", "AfterMessageTargetConversation",
        "Enabled", "Active", "TimeExpires", "UsePrimaryExtension", "PersonalCallTransfer",
    ) if key in record and not isinstance(record[key], (dict, list)))
    matches, edges = [], []
    for field, text in scalar_fields(record):
        leaf = field.rsplit(".", 1)[-1]
        lower = leaf.lower()
        if "targethandlerobjectid" in lower and text.strip():
            edges.append({"source": owner["id"], "target": text.strip(), "field": field,
                          "resource": resource, "context": context})
        if lower.endswith(("uri", "url", "objectid", "objectids")) or lower.startswith("@") or UUID.fullmatch(text):
            continue
        matches.append({"object_id": owner["id"], "object_name": owner["name"],
                        "object_type": owner["type"], "field": field, "value": text,
                        "resource": resource, "context": context,
                        "kind": "Number field" if NUMBER_FIELD.search(leaf) else "Text / setting occurrence"})
    return matches, edges


def find_matches(state):
    query = state["query"]
    mode = state["mode"]
    rows, keys = [], set()
    for item in state["fields"]:
        text = item["value"]
        tokens = re.findall(r"[0-9]+(?:[ ().+-]*[0-9]+)*", text)
        numbers = [re.sub(r"[^0-9]", "", token) for token in tokens]
        if not any(query == number if mode == "exact" else query in number for number in numbers):
            continue
        row = dict(item, reference="Direct", path="")
        owner = state["objects"].get(row["object_id"])
        if owner:
            row.update(object_name=owner["name"], object_type=owner["type"])
        key = (row["object_id"], row["resource"], row["field"], row["value"])
        if key not in keys:
            keys.add(key)
            rows.append(row)
    incoming = {}
    for edge in state["edges"]:
        incoming.setdefault(edge["target"], []).append(edge)
    direct = list(rows)
    for match in direct:
        pending = deque([(match["object_id"], [match["object_id"]])])
        visited = {match["object_id"]}
        emitted = set()
        while pending:
            target, path = pending.popleft()
            for edge in incoming.get(target, []):
                source = edge["source"]
                identity = (source, target, edge["resource"], edge["field"])
                if source in path or identity in emitted:
                    continue
                emitted.add(identity)
                owner = state["objects"].get(source, {"name": source, "type": "Unknown"})
                chain = [source] + path
                names = [state["objects"].get(identity, {}).get("name", identity) for identity in chain]
                rows.append({"object_id": source, "object_name": owner["name"], "object_type": owner["type"],
                             "field": edge["field"], "value": match["value"], "resource": edge["resource"],
                             "context": edge["context"], "kind": "Configured reference (review action)",
                             "reference": "Indirect", "path": " -> ".join(names) + " -> " + match["field"]})
                if source not in visited:
                    visited.add(source)
                    pending.append((source, chain))
                if len(rows) >= 50000:
                    raise UnitySearchError("Indirect reference result limit reached; use a narrower search.")
    return sorted(rows, key=lambda row: (row["object_type"], row["object_name"].lower(), row["reference"], row["resource"], row["field"]))


def timestamp():
    return datetime.now(timezone.utc).isoformat()


SEEDS = (
    ("System / primary call handlers", "/vmrest/handlers/callhandlers"),
    ("Users / mailboxes", "/vmrest/users"),
    ("Directory handlers", "/vmrest/handlers/directoryhandlers"),
    ("Interview handlers", "/vmrest/handlers/interviewhandlers"),
    ("Call routing rules", "/vmrest/routingrules"),
    ("Contacts", "/vmrest/contacts"),
    ("Call handler templates", "/vmrest/callhandlertemplates"),
    ("User templates", "/vmrest/usertemplates"),
    ("Phone systems", "/vmrest/phonesystems"),
    ("Port groups", "/vmrest/portgroups"),
    ("Restriction tables", "/vmrest/restrictiontables"),
    ("System configuration", "/vmrest/configuration"),
)
OPTIONAL_ROOTS = {path for _, path in SEEDS[2:]}
ALLOWED_ROOTS = {path.split("/")[2] for _, path in SEEDS}
ALLOWED_CHILDREN = {"greetings", "transferoptions", "menuentries", "alternateextensions",
                    "usernotificationdevices", "notificationdevices", "phonedevices", "pagerdevices",
                    "htmldevices", "messagewaitingindicators", "ruleconditions", "routingruleconditions",
                    "conditions", "rules", "restrictionpatterns", "pattern", "patterns", "ports"}
MAX_REQUESTS = 50000
PAGE_SIZE = 200


def safe_resource(value, host):
    parsed = urlsplit(str(value or ""))
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != "https" or parsed.netloc.lower() != host or parsed.username or parsed.password:
            raise UnitySearchError("Rejected cross-host or non-HTTPS CUPI link.")
    decoded = unquote(parsed.path)
    if parsed.query or parsed.fragment or ".." in decoded or "\\" in decoded or decoded.count("/") != parsed.path.count("/") or not re.fullmatch(r"/[A-Za-z0-9 /_.~-]+", decoded):
        raise UnitySearchError("Rejected unsafe CUPI resource link.")
    parts = decoded.strip("/").split("/")
    if len(parts) < 2 or parts[0] != "vmrest" or parts[1].lower() not in ALLOWED_ROOTS:
        raise UnitySearchError("Resource is outside the configuration search scope.")
    lowered = [part.lower() for part in parts]
    if any(EXCLUDED.search(part) or part in {"messages", "audio", "video", "password", "pin", "roles"} for part in lowered[2:]):
        raise UnitySearchError("Sensitive or media resource is excluded.")
    return quote(decoded.rstrip("/"), safe="/-._~")


def new_scan(host, query, mode="contains"):
    if mode not in {"exact", "contains"}:
        raise ValueError("Choose Exact or Contains matching.")
    return {"schema_version": 1, "host": normalize_host(host), "job_id": uuid.uuid4().hex,
            "query": normalize_query(query), "mode": mode, "status": "running", "started_at": timestamp(),
            "updated_at": timestamp(), "tasks": [{"resource": path, "label": label, "page": 0, "owner": None} for label, path in SEEDS],
            "scheduled": [path for _, path in SEEDS], "page_signatures": {}, "objects": {},
            "fields": [], "edges": [], "coverage": [], "excluded_links": [], "requests": 0,
            "records": 0, "retention": RETENTION, "limitations": LIMITS}


def new_cache_scan(host, query="", mode="contains"):
    state = new_scan(host, query or "000", mode)
    state["query"] = normalize_query(query) if query else ""
    state["collect_all_numbers"] = True
    return state


COLLECTION_NAMES = {"callhandler", "user", "directoryhandler", "interviewhandler", "routingrule", "contact",
                    "callhandlertemplate", "usertemplate", "phonesystem", "portgroup", "restrictiontable",
                    "transferoption", "greeting", "menuentry", "alternateextension", "notificationdevice",
                    "usernotificationdevice", "phonedevice", "pagerdevice", "htmldevice", "messagewaitingindicator",
                    "rulecondition", "routingrulecondition", "condition", "restrictionpattern", "pattern"}


def _response_shape(payload):
    return ", ".join(str(key)[:60] + ":" + type(value).__name__ for key, value in list(payload.items())[:20])


def _records(payload, depth=0):
    if not isinstance(payload, dict):
        raise UnitySearchError("CUPI returned an unexpected JSON shape.")
    if "URI" in payload or "ObjectId" in payload:
        return [payload], None
    total = payload.get("@total", payload.get("total"))
    try:
        total = int(total) if total is not None else None
    except (ValueError, TypeError):
        raise UnitySearchError("CUPI returned an invalid collection count.") from None
    if total is not None and total < 0:
        raise UnitySearchError("CUPI returned a negative collection count.")
    named = []
    for key, value in payload.items():
        name = re.sub(r"[^a-z]", "", str(key).lower())
        singular = name[:-3] + "y" if name.endswith("ies") else name[:-1] if name.endswith("s") else name
        if name in COLLECTION_NAMES or singular in COLLECTION_NAMES:
            named.append(value)
    if len(named) > 1:
        raise UnitySearchError("CUPI returned ambiguous collections; response shape: " + _response_shape(payload))
    if named:
        container = named[0]
        if isinstance(container, dict) and "URI" not in container and "ObjectId" not in container and any(isinstance(value, (dict, list)) for value in container.values()):
            if depth >= 3:
                raise UnitySearchError("CUPI collection wrapper depth exceeded.")
            records, nested_total = _records(container, depth + 1)
            return records, total if total is not None else nested_total
        if container is None and total == 0:
            return [], 0
        records = container if isinstance(container, list) else [container]
        if any(not isinstance(item, dict) for item in records):
            raise UnitySearchError("CUPI collection contains invalid records; response shape: " + _response_shape(payload))
        return records, total
    containers = [value for key, value in payload.items() if not str(key).startswith("@") and str(key).lower() not in {"links", "link", "metadata", "paging", "pagination"} and isinstance(value, (dict, list))]
    if len(containers) != 1:
        if total == 0 and not containers:
            return [], 0
        if total is not None and total > 0 and not containers:
            raise UnityCountOnlyPage(total)
        raise UnitySearchError("CUPI collection records were not identifiable; response shape: " + _response_shape(payload))
    container = containers[0]
    records = container if isinstance(container, list) else [container]
    if any(not isinstance(item, dict) for item in records):
        raise UnitySearchError("CUPI collection contains invalid records.")
    return records, total


def _schedule(state, resource, label, owner=None):
    scheduled = state.get("_scheduled_index")
    if scheduled is None:
        scheduled = dict.fromkeys(state["scheduled"])
        state["_scheduled_index"] = scheduled
    if resource in scheduled:
        return
    if len(state["scheduled"]) >= MAX_REQUESTS:
        raise UnitySearchError("CUPI resource limit reached; scan is incomplete.")
    state["scheduled"].append(resource)
    scheduled[resource] = None
    state["tasks"].append({"resource": resource, "label": label, "page": 0, "owner": owner})


def _matches_query(field, state):
    tokens = re.findall(r"[0-9]+(?:[ ().+-]*[0-9]+)*", field["value"])
    for token in tokens:
        digits = re.sub(r"[^0-9]", "", token)
        if (state["mode"] == "exact" and digits == state["query"]) or (state["mode"] == "contains" and state["query"] in digits):
            return True
    return False


COLLECTION_REQUIRED_FIELDS = {
    "greetings": {"URI", "CallHandlerObjectId", "GreetingType", "AfterGreetingAction", "AfterGreetingTargetConversation", "AfterGreetingTargetHandlerObjectId", "TimeExpires", "Enabled", "IgnoreDigits", "PlayWhat", "RepromptDelay", "Reprompts"},
    "transferoptions": {"URI", "CallHandlerObjectId", "TransferOptionType", "Action", "Extension", "RnaAction", "TimeExpires", "TransferType", "UsePrimaryExtension", "PersonalCallTransfer", "Enabled"},
}


def _collection_fingerprint(record):
    def sanitized(value):
        if isinstance(value, dict):
            return {str(key): sanitized(item) for key, item in value.items() if not EXCLUDED.search(str(key))}
        if isinstance(value, list):
            return [sanitized(item) for item in value]
        return value
    value = sanitized(record)
    schema = hashlib.sha256(json.dumps(sorted(value), ensure_ascii=True).encode()).hexdigest()
    fingerprint = hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    return schema, fingerprint


def _collection_reusable(state, record, task, resource):
    candidates = state.setdefault("collection_candidates", {})
    verified = state.setdefault("verified_collection_schemas", {})
    mismatches = state.setdefault("collection_mismatch_families", {})
    candidate = candidates.get(task["resource"])
    if candidate and not mismatches.get(candidate["family"]):
        schema, fingerprint = _collection_fingerprint(record)
        if schema == candidate["schema"] and fingerprint == candidate["fingerprint"]:
            verified[candidate["family"]] = schema
            inflight = state.get("_inflight_resources", {})
            for pending in list(state["tasks"]):
                evidence = candidates.get(pending["resource"])
                if evidence and pending["resource"] != task["resource"] and pending["resource"] not in inflight and evidence["family"] == candidate["family"] and evidence["schema"] == schema and not pending.get("page"):
                    state["tasks"].remove(pending)
                    state["coverage"].append({"resource": pending["resource"], "status": "Checked", "detail": "Complete collection record reused after matching detail verification."})
        else:
            mismatches[candidate["family"]] = True
            verified.pop(candidate["family"], None)
    family = task["resource"].rsplit("/", 1)[-1]
    required = COLLECTION_REQUIRED_FIELDS.get(family)
    if not required or not required.issubset(record) or not resource.startswith(task["resource"] + "/"):
        return False
    if not task["resource"].startswith(("/vmrest/handlers/callhandlers/", "/vmrest/callhandlertemplates/")):
        return False
    family = task["resource"].split("/")[2] + "/" + family
    schema, fingerprint = _collection_fingerprint(record)
    candidates[resource] = {"family": family, "schema": schema, "fingerprint": fingerprint}
    return not mismatches.get(family) and verified.get(family) == schema


def _ingest(state, record, task):
    resource = task["resource"]
    owner = task["owner"]
    if owner is not None:
        owner = state["objects"].get(owner["id"], owner)
        if record.get("DisplayName"):
            owner = dict(owner, name=str(record["DisplayName"]))
        state["objects"][owner["id"]] = owner
    if owner is None:
        identity = str(record.get("ObjectId") or str(record.get("URI") or resource).rstrip("/").rsplit("/", 1)[-1])
        owner = {"id": identity, "name": str(record.get("DisplayName") or record.get("Alias") or record.get("Name") or identity),
                 "type": task["label"]}
        if resource == "/vmrest/handlers/callhandlers":
            owner["type"] = "Call Handler (type not returned)" if "IsPrimary" not in record else "Primary user call handler" if str(record["IsPrimary"]).lower() == "true" else "System Call Handler"
        state["objects"][identity] = owner
    item_resource = str(record.get("URI") or resource)
    try:
        canonical_item = safe_resource(item_resource, state["host"])
    except UnitySearchError:
        canonical_item = resource
    reusable = _collection_reusable(state, record, task, canonical_item)
    fields, edges = record_evidence(record, owner, item_resource)
    if state.get("collect_all_numbers"):
        state["fields"].extend(field for field in fields if any(len(re.sub(r"[^0-9]", "", token)) >= 3 for token in re.findall(r"[0-9]+(?:[ ().+-]*[0-9]+)*", field["value"])))
    else:
        state["fields"].extend(field for field in fields if _matches_query(field, state))
    state["edges"].extend(edges)
    if str(record.get("PersonalCallTransfer", "false")).lower() == "true":
        state["excluded_links"].append({"resource": item_resource, "reason": "Personal call-transfer rules enabled; not searched."})
    for field, value in scalar_fields(record):
        if not field.lower().endswith("uri") or not value:
            continue
        leaf = field.rsplit(".", 1)[-1].lower()
        try:
            link = safe_resource(value, state["host"])
        except UnitySearchError:
            if leaf not in {"uri", "voicenameuri", "voicefileuri"}:
                state["excluded_links"].append({"resource": item_resource, "reason": f"{field}: excluded/untrusted resource link"})
            continue
        parts = link.strip("/").split("/")
        is_root_item = len(parts) == (4 if parts[1].lower() == "handlers" else 3)
        is_child = any(part.lower() in ALLOWED_CHILDREN for part in parts[2:])
        if is_root_item:
            if leaf == "uri" and task["owner"] is not None:
                continue
            linked_owner = owner
            if leaf != "uri":
                identity = parts[-1]
                primary = parts[1:3] == ["handlers", "callhandlers"] and resource.startswith("/vmrest/users")
                linked_owner = state["objects"].get(identity, {"id": identity,
                    "name": owner["name"] + " (primary handler)" if primary else identity,
                    "type": "Primary user call handler" if primary else parts[-2]})
                state["objects"].setdefault(identity, linked_owner)
            _schedule(state, link, linked_owner["type"], linked_owner)
        elif is_child:
            if leaf == "uri" and reusable and link == canonical_item:
                state["coverage"].append({"resource": link, "status": "Checked", "detail": "Complete collection record reused after matching detail verification."})
            else:
                _schedule(state, link, owner["type"], owner)
                candidate = state["collection_candidates"].get(link)
                if candidate and not state["verified_collection_schemas"].get(candidate["family"]):
                    for pending in reversed(state["tasks"]):
                        if pending["resource"] == link:
                            pending["probe"] = True
                            break
        elif leaf != "uri":
            state["excluded_links"].append({"resource": item_resource, "reason": f"{field}: resource outside covered child collections"})
    if task["owner"] is None and record.get("URI"):
        try:
            detail = safe_resource(record["URI"], state["host"])
            _schedule(state, detail, owner["type"], owner)
            if resource == "/vmrest/handlers/callhandlers":
                for child in ("transferoptions", "menuentries", "greetings"):
                    _schedule(state, detail + "/" + child, owner["type"], owner)
            elif resource == "/vmrest/users":
                for child in ("alternateextensions", "usernotificationdevices", "messagewaitingindicators"):
                    _schedule(state, detail + "/" + child, owner["type"], owner)
        except UnitySearchError as exc:
            state["coverage"].append({"resource": resource, "status": "Failed", "detail": str(exc)})


def advance_scan(state, username, password, session=None, task=None):
    if state["status"] != "running":
        return state
    if not username or not password:
        raise UnitySearchError("Unity session credentials expired; log in again, then Resume.")
    if not state["tasks"] or state["requests"] >= MAX_REQUESTS:
        state["status"] = "completed" if not state["tasks"] else "failed"
        state["updated_at"] = timestamp()
        return state
    task = task or state["tasks"][0]
    state.setdefault("_dirty_tasks", {})[task["resource"]] = None
    resource = safe_resource(task["resource"], state["host"])
    owned_session = session is None
    client = session or requests.Session()
    try:
        response = client.get("https://" + state["host"] + resource,
                              params={"rowsPerPage": PAGE_SIZE, "pageNumber": task["page"]},
                              auth=(username, password), headers={"Accept": "application/json"},
                              verify=False, timeout=(5, 15), allow_redirects=False)
        if response.status_code in {401, 403}:
            state["status"] = "paused"
            raise UnitySearchError(f"Unity denied read access (HTTP {response.status_code}); renew credentials/permissions and Resume.")
        state["requests"] += 1
        if response.status_code == 404 and resource in OPTIONAL_ROOTS and task["page"] == 0 and state.get("collect_all_numbers"):
            state["tasks"].remove(task)
            detail = "Optional CUPI inventory endpoint is not supported (HTTP 404); this resource was not searched."
            state["coverage"].append({"resource": resource, "status": "Unsupported", "detail": detail})
            state["excluded_links"].append({"resource": resource, "reason": detail})
            if not state["tasks"]:
                state["status"] = "completed"
            return state
        if response.status_code != 200:
            raise UnitySearchError(f"CUPI read failed HTTP {response.status_code}; resource not checked.")
        records, total = _records(response.json())
        if task.get("count_only_retry") and not records and not task.get("consumed", 0):
            raise UnitySearchError("CUPI page 1 returned no records after a positive count-only page 0; inventory remains incomplete.")
        if total is None and task.get("count_only_total") is not None:
            total = task["count_only_total"]
        signature = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
        previous = state["page_signatures"].setdefault(resource, [])
        if records and signature in previous:
            raise UnitySearchError("CUPI repeated a page; pagination incomplete.")
        if records:
            previous.append(signature)
            state.setdefault("_dirty_mappings", {}).setdefault("page_signatures", {})[resource] = None
        if not records and total and task.get("consumed", 0) < total:
            raise UnitySearchError("CUPI returned an empty page before the reported total.")
        for record in records:
            _ingest(state, record, task)
        state["records"] += len(records)
        consumed = task.get("consumed", 0) + len(records)
        more = consumed < total if total is not None else len(records) == PAGE_SIZE
        if more:
            if not records or task["page"] >= 999:
                raise UnitySearchError("CUPI collection page limit reached; resource incomplete.")
            task["consumed"] = consumed
            task["page"] += 1
        else:
            state["tasks"].remove(task)
            state["coverage"].append({"resource": resource, "status": "Checked", "detail": f"{consumed} records read"})
    except UnityCountOnlyPage as exc:
        if task["page"] == 0 and not task.get("consumed", 0):
            task["page"] = 1
            task["count_only_retry"] = True
            task["count_only_total"] = exc.total
        else:
            state["tasks"].remove(task)
            state["coverage"].append({"resource": resource, "status": "Failed", "detail": str(exc) + " Page-1 retry did not return records."})
    except UnitySearchError as exc:
        if state["status"] == "paused":
            raise
        state["tasks"].remove(task)
        state["coverage"].append({"resource": resource, "status": "Failed", "detail": str(exc)})
    except (requests.RequestException, ValueError):
        state["requests"] += 1
        state["tasks"].remove(task)
        state["coverage"].append({"resource": resource, "status": "Failed", "detail": "CUPI network/JSON read failed; resource not checked."})
    finally:
        if owned_session:
            client.close()
        state["updated_at"] = timestamp()
    if not state["tasks"]:
        state["status"] = "completed"
    return state


def scan_report(state):
    rows = find_matches(state) if state["query"] and not (state.get("collect_all_numbers") and state["status"] != "completed") else []
    failures = [item for item in state["coverage"] if item["status"] not in {"Checked", "Unsupported"}]
    gaps = [item for item in state["coverage"] if item["status"] != "Checked"]
    excluded = list({(item["resource"], item["reason"]): item for item in state["excluded_links"]}.values())
    return {"schema_version": 1, "host": state["host"], "job_id": state["job_id"], "query": state["query"],
            "mode": state["mode"], "status": state["status"], "started_at": state["started_at"], "checked_at": state["updated_at"],
            "rows": rows, "match_count": len(rows), "requests": state["requests"], "records": state["records"],
            "pending_resources": len(state["tasks"]), "coverage": state["coverage"], "failures": failures,
            "excluded_links": excluded, "complete": state["status"] == "completed" and not gaps,
            "cache_ready": state["status"] == "completed" and not failures, "coverage_gaps": gaps,
            "retention": RETENTION, "limitations": LIMITS, "cache_build": bool(state.get("collect_all_numbers"))}


def progress_report(state):
    if state["status"] not in {"running", "paused"}:
        return scan_report(state)
    report = {"schema_version": 1, "host": state["host"], "job_id": state["job_id"], "query": state["query"],
              "mode": state["mode"], "status": state["status"], "started_at": state["started_at"], "checked_at": state["updated_at"],
              "rows": [], "match_count": 0, "requests": state["requests"], "records": state["records"],
              "pending_resources": len(state["tasks"]), "coverage": [], "failures": [], "excluded_links": [],
              "complete": False, "cache_ready": False, "cache_build": bool(state.get("collect_all_numbers")),
              "retention": RETENTION, "limitations": LIMITS, "progress_only": True,
              "checked_resources": len(state["coverage"]), "concurrency": 2, "requests_per_second": 2}
    for item in state["coverage"]:
        if item["status"] not in {"Checked", "Unsupported"}:
            report["failures"].append(item)
    report["failure_count"] = len(report["failures"])
    report["failures"] = report["failures"][-20:]
    return report


class _BufferedRead:
    def __init__(self, future):
        self.future = future

    def get(self, *args, **kwargs):
        return self.future.result()


def advance_parallel(state, username, password, checkpoint, session_factory=None):
    if state["status"] != "running":
        return state
    if not username or not password:
        raise UnitySearchError("Unity session credentials expired; log in again, then Resume.")
    tasks = sorted(state["tasks"], key=lambda task: not task.get("probe", False))[:min(4, max(0, MAX_REQUESTS - state["requests"]))]
    if not tasks:
        return advance_scan(state, username, password)
    session_factory = session_factory or requests.Session
    local = threading.local()
    clients = []
    lock = threading.Lock()
    cancelled = threading.Event()
    last_started = [min(float(state.get("last_read_started_at", 0)), time.time())]
    state["_inflight_resources"] = dict.fromkeys(task["resource"] for task in tasks)

    def fetch(task):
        resource = safe_resource(task["resource"], state["host"])
        with lock:
            wait = max(0, 0.5 - (time.time() - last_started[0]))
            if cancelled.wait(wait):
                raise requests.RequestException("Parallel read cancelled before submission.")
            last_started[0] = time.time()
        if not hasattr(local, "client"):
            local.client = session_factory()
            with lock:
                clients.append(local.client)
        return local.client.get("https://" + state["host"] + resource,
                                params={"rowsPerPage": PAGE_SIZE, "pageNumber": task["page"]},
                                auth=(username, password), headers={"Accept": "application/json"},
                                verify=False, timeout=(5, 15), allow_redirects=False)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [(task, executor.submit(fetch, dict(task))) for task in tasks]
            for task, future in futures:
                try:
                    advance_scan(state, username, password, _BufferedRead(future), task=task)
                except UnitySearchError:
                    cancelled.set()
                    state["last_read_started_at"] = last_started[0]
                    checkpoint(state)
                    raise
                state["last_read_started_at"] = last_started[0]
                if state["status"] != "completed":
                    checkpoint(state)
    finally:
        cancelled.set()
        state.pop("_inflight_resources", None)
        for client in clients:
            client.close()
    return state


def cache_metadata(cache, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        cached_at = datetime.fromisoformat(cache["cached_at"].replace("Z", "+00:00"))
        if cached_at.tzinfo is None or now.tzinfo is None:
            raise ValueError("Timezone required")
        age = (now - cached_at).total_seconds()
        if age < 0:
            raise ValueError("Future timestamp")
    except (KeyError, TypeError, ValueError, AttributeError):
        raise UnitySearchError("Unity cache timestamp is invalid; cache was not overwritten.") from None
    return {"available": True, "fresh": age < CACHE_TTL_SECONDS, "cached_at": cached_at.isoformat(),
            "loaded_at": cache["loaded_at"], "expires_at": (cached_at + timedelta(seconds=CACHE_TTL_SECONDS)).isoformat(),
            "age_seconds": int(age), "ttl_seconds": CACHE_TTL_SECONDS, "field_count": len(cache["fields"]) if "fields" in cache else cache["field_count"]}


_CACHE_INFO = {}
_CACHE_INFO_LOCK = threading.Lock()


def cache_info(root, host):
    path = _path(root, host, "cache")
    try:
        details = os.stat(path)
    except FileNotFoundError:
        return {"available": False, "fresh": False, "ttl_seconds": CACHE_TTL_SECONDS}
    signature = (details.st_mtime_ns, details.st_size, details.st_ino)
    with _CACHE_INFO_LOCK:
        previous = _CACHE_INFO.get(path)
        if previous is None or previous[0] != signature:
            metadata = cache_metadata(load(root, host, "cache"))
            _CACHE_INFO[path] = (signature, metadata)
        return cache_metadata(_CACHE_INFO[path][1])


def completed_cache(state):
    if not state.get("collect_all_numbers") or state["status"] != "completed" or state["tasks"] or any(item["status"] not in {"Checked", "Unsupported"} for item in state["coverage"]):
        raise UnitySearchError("Cache load is incomplete; previous cache is retained.")
    cache = {key: state[key] for key in ("schema_version", "host", "job_id", "status", "started_at", "updated_at",
                                        "objects", "edges", "coverage", "excluded_links", "requests", "records")}
    cache.update(cache_version=1, query="", mode="contains", collect_all_numbers=True,
                 fields=list({(item["object_id"], item["resource"], item["field"], item["value"]): item for item in state["fields"]}.values()),
                 tasks=[], cached_at=state["started_at"], loaded_at=state["updated_at"])
    cache_metadata(cache)
    return cache


def search_cache(cache, query, mode="contains", now=None):
    metadata = cache_metadata(cache, now)
    if not metadata["fresh"]:
        raise UnitySearchError("Unity cache is eight hours old or older; load new cache before searching.")
    if mode not in {"exact", "contains"}:
        raise ValueError("Choose Exact or Contains matching.")
    state = dict(cache, query=normalize_query(query), mode=mode, job_id=uuid.uuid4().hex,
                 updated_at=(now or datetime.now(timezone.utc)).isoformat())
    report = scan_report(state)
    report.update(cache=metadata, cache_build=False, source="cache")
    return report


def _path(root, host, kind):
    if kind not in {"scan", "report", "cache"}:
        raise ValueError("Invalid saved lookup type.")
    return os.path.join(root, hashlib.sha256(normalize_host(host).encode()).hexdigest() + "_" + kind + ".json")


def load(root, host, kind="scan", _json_only=False):
    if kind == "scan" and not _json_only and os.path.exists(_scan_db_path(root, host)):
        value = _load_incremental(root, host)
    else:
        with open(_path(root, host, kind), encoding="utf-8") as handle:
            value = json.load(handle)
    lists = ("tasks", "fields", "edges", "coverage", "excluded_links", "scheduled") if kind == "scan" else ("fields", "edges", "coverage", "excluded_links") if kind == "cache" else ("rows", "coverage", "failures", "excluded_links")
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("host") != normalize_host(host) or any(not isinstance(value.get(key), list) for key in lists) or not value.get("job_id") or value.get("status") not in {"running", "paused", "cancelled", "failed", "completed"}:
        raise UnitySearchError("Saved Unity lookup is invalid; it was not overwritten.")
    if kind == "cache":
        if value.get("cache_version") != 1 or not isinstance(value.get("objects"), dict) or value["status"] != "completed" or value.get("tasks") != [] or not value.get("collect_all_numbers") or any(item.get("status") not in {"Checked", "Unsupported"} for item in value["coverage"]):
            raise UnitySearchError("Unity configuration cache is invalid; it was not overwritten.")
        cache_metadata(value)
    return value


def save(root, value, kind="scan", _json_only=False):
    if kind == "scan" and not _json_only and (value.get("_incremental") or os.path.exists(_scan_db_path(root, value["host"]))):
        _save_incremental(root, value)
        return
    value = {key: item for key, item in value.items() if not key.startswith("_")}
    path = _path(root, value["host"], kind)
    os.makedirs(root, exist_ok=True)
    if os.path.exists(path):
        load(root, value["host"], kind, _json_only=_json_only)
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as handle:
            temp_path = handle.name
            os.chmod(temp_path, 0o600)
            handle.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")))
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(3):
            try:
                os.replace(temp_path, path)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
        temp_path = ""
        if os.name != "nt":
            directory = os.open(root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temp_path:
            os.unlink(temp_path)


SCAN_ARRAYS = ("fields", "edges", "coverage", "excluded_links", "scheduled")
SCAN_MAPPINGS = {"objects": "objects", "page_signatures": "signatures", "collection_candidates": "collection_candidates", "verified_collection_schemas": "verified_collection_schemas", "collection_mismatch_families": "collection_mismatch_families"}
SCAN_STRUCTURES = set(SCAN_ARRAYS) | {"tasks"} | set(SCAN_MAPPINGS)


def _compact(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _scan_db_path(root, host):
    return _path(root, host, "scan") + ".sqlite3"


def _scan_metadata(state):
    return {key: value for key, value in state.items() if key not in SCAN_STRUCTURES and not key.startswith("_")}


def _load_incremental(root, host):
    path = _scan_db_path(root, host)
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute("BEGIN")
        metadata = dict(connection.execute("SELECT name, data FROM metadata"))
        state = {key: json.loads(value) for key, value in metadata.items() if not key.startswith("_")}
        state["_db_revision"] = int(metadata["_revision"])
        task_rows = list(connection.execute("SELECT resource, position, data FROM tasks ORDER BY position"))
        state["tasks"] = [json.loads(row[2]) for row in task_rows]
        state["_db_tasks"] = {row[0]: (row[1], row[2]) for row in task_rows}
        state["_db_task_ids"] = {task["resource"]: id(task) for task in state["tasks"]}
        state["_db_position"] = max((row[1] for row in task_rows), default=-1)
        for category in SCAN_ARRAYS:
            state[category] = [json.loads(row[0]) for row in connection.execute("SELECT data FROM arrays WHERE category=? ORDER BY position", (category,))]
        for key, category in SCAN_MAPPINGS.items():
            state[key] = {identity: json.loads(data) for identity, data in connection.execute("SELECT identity, data FROM mappings WHERE category=?", (category,))}
        state["_db_counts"] = {key: len(state[key]) for key in SCAN_ARRAYS}
        state["_db_array_ids"] = {key: id(state[key]) for key in SCAN_ARRAYS}
        state["_db_mappings"] = {key: {identity: _compact(value) for identity, value in state[key].items()} for key in SCAN_MAPPINGS}
        state["_db_mapping_ids"] = {key: {identity: id(value) for identity, value in state[key].items()} for key in SCAN_MAPPINGS}
        state["_incremental"] = True
        return state
    except (sqlite3.Error, KeyError, ValueError, TypeError) as exc:
        raise UnitySearchError("Incremental Unity scan checkpoint is invalid; it was not overwritten.") from exc
    finally:
        connection.close()


def _db_schema(connection):
    connection.execute("CREATE TABLE metadata (name TEXT PRIMARY KEY, data TEXT NOT NULL)")
    connection.execute("CREATE TABLE tasks (resource TEXT PRIMARY KEY, position INTEGER NOT NULL, data TEXT NOT NULL)")
    connection.execute("CREATE TABLE arrays (category TEXT NOT NULL, position INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(category, position))")
    connection.execute("CREATE TABLE mappings (category TEXT NOT NULL, identity TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(category, identity))")


def _db_seed(connection, state, revision=0):
    for table in ("metadata", "tasks", "arrays", "mappings"):
        connection.execute("DELETE FROM " + table)
    connection.executemany("INSERT INTO metadata VALUES (?,?)", ((key, _compact(value)) for key, value in _scan_metadata(state).items()))
    connection.execute("INSERT INTO metadata VALUES ('_revision',?)", (str(revision),))
    connection.executemany("INSERT INTO tasks VALUES (?,?,?)", ((task["resource"], index, _compact(task)) for index, task in enumerate(state["tasks"])))
    for category in SCAN_ARRAYS:
        connection.executemany("INSERT INTO arrays VALUES (?,?,?)", ((category, index, _compact(value)) for index, value in enumerate(state[category])))
    for key, category in SCAN_MAPPINGS.items():
        connection.executemany("INSERT INTO mappings VALUES (?,?,?)", ((category, identity, _compact(value)) for identity, value in state.get(key, {}).items()))


def enable_incremental(root, state):
    if state.get("_incremental"):
        return state
    path = _scan_db_path(root, state["host"])
    if os.path.exists(path):
        existing = load(root, state["host"])
        if existing["job_id"] != state["job_id"]:
            raise UnitySearchError("Unity scan changed; reload the latest scan before resuming.")
        return existing
    load(root, state["host"])
    os.makedirs(root, exist_ok=True)
    temporary = ""
    try:
        with tempfile.NamedTemporaryFile(dir=root, delete=False) as handle:
            temporary = handle.name
        os.chmod(temporary, 0o600)
        connection = sqlite3.connect(temporary)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                _db_schema(connection)
                _db_seed(connection, state)
        finally:
            connection.close()
        os.replace(temporary, path)
        temporary = ""
        if os.name != "nt":
            directory = os.open(root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary:
            os.unlink(temporary)
    return load(root, state["host"])


def _save_incremental(root, state):
    path = _scan_db_path(root, state["host"])
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        metadata = dict(connection.execute("SELECT name, data FROM metadata"))
        revision = int(metadata["_revision"])
        if json.loads(metadata["job_id"]) != state["job_id"]:
            _db_seed(connection, state, revision + 1)
        else:
            if state.get("_db_revision", revision) != revision:
                raise UnitySearchError("Unity scan changed in another request; reload saved progress.")
            previous_tasks = state.get("_db_tasks") or {resource: (position, data) for resource, position, data in connection.execute("SELECT resource, position, data FROM tasks")}
            current_tasks = {task["resource"]: task for task in state["tasks"]}
            removed = previous_tasks.keys() - current_tasks.keys()
            connection.executemany("DELETE FROM tasks WHERE resource=?", ((resource,) for resource in removed))
            next_position = max(state.get("_db_position", -1), max((value[0] for value in previous_tasks.values()), default=-1))
            task_values = {}
            for resource, task in current_tasks.items():
                previous = previous_tasks.get(resource)
                unchanged = previous and state.get("_db_task_ids", {}).get(resource) == id(task) and resource not in state.get("_dirty_tasks", {})
                data = previous[1] if unchanged else _compact(task)
                if previous is None:
                    next_position += 1
                position = previous[0] if previous else next_position
                task_values[resource] = (position, data)
                if previous is None or data != previous[1]:
                    connection.execute("INSERT OR REPLACE INTO tasks VALUES (?,?,?)", (resource, position, data))
            for category in SCAN_ARRAYS:
                count = state.get("_db_counts", {}).get(category)
                if count is None:
                    count = connection.execute("SELECT COUNT(*) FROM arrays WHERE category=?", (category,)).fetchone()[0]
                if len(state[category]) < count or state.get("_db_array_ids", {}).get(category, id(state[category])) != id(state[category]):
                    connection.execute("DELETE FROM arrays WHERE category=?", (category,))
                    count = 0
                connection.executemany("INSERT INTO arrays VALUES (?,?,?)", ((category, index, _compact(value)) for index, value in enumerate(state[category][count:], count)))
            mapping_values = {}
            for key, category in SCAN_MAPPINGS.items():
                previous = state.get("_db_mappings", {}).get(key)
                if previous is None:
                    previous = dict(connection.execute("SELECT identity, data FROM mappings WHERE category=?", (category,)))
                values = {identity: previous[identity] if identity in previous and state.get("_db_mapping_ids", {}).get(key, {}).get(identity) == id(value) and identity not in state.get("_dirty_mappings", {}).get(key, {}) else _compact(value) for identity, value in state.get(key, {}).items()}
                mapping_values[key] = values
                connection.executemany("DELETE FROM mappings WHERE category=? AND identity=?", ((category, identity) for identity in previous.keys() - values.keys()))
                connection.executemany("INSERT OR REPLACE INTO mappings VALUES (?,?,?)", ((category, identity, data) for identity, data in values.items() if previous.get(identity) != data))
            connection.executemany("INSERT OR REPLACE INTO metadata VALUES (?,?)", ((key, _compact(value)) for key, value in _scan_metadata(state).items()))
            connection.execute("UPDATE metadata SET data=? WHERE name='_revision'", (str(revision + 1),))
        connection.commit()
        state["_db_revision"] = revision + 1
        state["_db_tasks"] = {task["resource"]: (index, _compact(task)) for index, task in enumerate(state["tasks"])} if json.loads(metadata["job_id"]) != state["job_id"] else task_values
        state["_db_position"] = max((value[0] for value in state["_db_tasks"].values()), default=-1)
        state["_db_task_ids"] = {task["resource"]: id(task) for task in state["tasks"]}
        state["_db_counts"] = {key: len(state[key]) for key in SCAN_ARRAYS}
        state["_db_array_ids"] = {key: id(state[key]) for key in SCAN_ARRAYS}
        state["_db_mappings"] = {key: {identity: _compact(value) for identity, value in state.get(key, {}).items()} for key in SCAN_MAPPINGS} if json.loads(metadata["job_id"]) != state["job_id"] else mapping_values
        state["_db_mapping_ids"] = {key: {identity: id(value) for identity, value in state.get(key, {}).items()} for key in SCAN_MAPPINGS}
        state.pop("_dirty_tasks", None)
        state.pop("_dirty_mappings", None)
        state["_incremental"] = True
    finally:
        connection.close()
    if state["status"] in {"paused", "cancelled", "completed", "failed"}:
        save(root, state, _json_only=True)
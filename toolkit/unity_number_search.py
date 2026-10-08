import hashlib
import json
import os
import re
import tempfile
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
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
    if resource in state["scheduled"]:
        return
    if len(state["scheduled"]) >= MAX_REQUESTS:
        raise UnitySearchError("CUPI resource limit reached; scan is incomplete.")
    state["scheduled"].append(resource)
    state["tasks"].append({"resource": resource, "label": label, "page": 0, "owner": owner})


def _matches_query(field, state):
    tokens = re.findall(r"[0-9]+(?:[ ().+-]*[0-9]+)*", field["value"])
    for token in tokens:
        digits = re.sub(r"[^0-9]", "", token)
        if (state["mode"] == "exact" and digits == state["query"]) or (state["mode"] == "contains" and state["query"] in digits):
            return True
    return False


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
            _schedule(state, link, owner["type"], owner)
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


def advance_scan(state, username, password, session=None):
    if state["status"] != "running":
        return state
    if not username or not password:
        raise UnitySearchError("Unity session credentials expired; log in again, then Resume.")
    if not state["tasks"] or state["requests"] >= MAX_REQUESTS:
        state["status"] = "completed" if not state["tasks"] else "failed"
        state["updated_at"] = timestamp()
        return state
    task = state["tasks"][0]
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
            state["tasks"].pop(0)
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
            state["tasks"].pop(0)
            state["coverage"].append({"resource": resource, "status": "Checked", "detail": f"{consumed} records read"})
    except UnityCountOnlyPage as exc:
        if task["page"] == 0 and not task.get("consumed", 0):
            task["page"] = 1
            task["count_only_retry"] = True
            task["count_only_total"] = exc.total
        else:
            state["tasks"].pop(0)
            state["coverage"].append({"resource": resource, "status": "Failed", "detail": str(exc) + " Page-1 retry did not return records."})
    except UnitySearchError as exc:
        if state["status"] == "paused":
            raise
        state["tasks"].pop(0)
        state["coverage"].append({"resource": resource, "status": "Failed", "detail": str(exc)})
    except (requests.RequestException, ValueError):
        state["requests"] += 1
        state["tasks"].pop(0)
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


def load(root, host, kind="scan"):
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


def save(root, value, kind="scan"):
    path = _path(root, value["host"], kind)
    os.makedirs(root, exist_ok=True)
    if os.path.exists(path):
        load(root, value["host"], kind)
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as handle:
            temp_path = handle.name
            os.chmod(temp_path, 0o600)
            json.dump(value, handle, ensure_ascii=True)
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
import hashlib
import importlib.util
import json
import os
import re
import shlex
import tempfile
import time
from datetime import datetime, timezone


class UnitySqlError(RuntimeError):
    pass


RESULT_COLUMNS = ("owner_name", "primary_extension", "matched_field", "matched_number", "setting")
MAX_ROWS = 500
SSH_TIMEOUT_SECONDS = 12
MAX_OUTPUT_BYTES = 2_000_000
RETENTION = "Latest successful lookup per Unity host only; not an archive. Runtime data survives normal restarts and code pulls, not deletion or older VM/data restores."
LIMITATIONS = "Verified SQL scope: mailbox alternate-contact TransferNumber, user/handler transfer-option Extension, and primary DtmfAccessId. Standalone System Call Handler menu-entry ownership is not included until its view/schema is verified. Results are stored configuration, not proof of an active call path."


def configuration_status(environ=None):
    environ = os.environ if environ is None else environ
    enabled = str(environ.get("UNITY_SQL_LOOKUP_ENABLED", "")).strip().lower() in {"1", "true", "yes", "on"}
    required = (
        "UNITY_SQL_LOOKUP_SSH_USER",
        "UNITY_SQL_LOOKUP_SSH_PASSWORD",
        "UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE",
    )
    missing = [name for name in required if not str(environ.get(name, "")).strip()]
    if enabled and not missing:
        username = str(environ["UNITY_SQL_LOOKUP_SSH_USER"]).strip()
        if not username or len(username) > 128 or any(not (character.isalnum() or character in "._@\\-") for character in username):
            missing.append("UNITY_SQL_LOOKUP_SSH_USER (invalid)")
        known_hosts_file = os.path.abspath(os.path.expanduser(str(environ["UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE"]).strip()))
        if not os.path.isfile(known_hosts_file):
            missing.append("UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE (unavailable)")
        if importlib.util.find_spec("paramiko") is None:
            missing.append("Paramiko library")
    return {"enabled": enabled, "configured": enabled and not missing, "missing": missing, "read_only": True}


def _ssh_configuration(unity_host, environ=None):
    environ = os.environ if environ is None else environ
    status = configuration_status(environ)
    if not status["enabled"]:
        raise UnitySqlError("Unity SQL Lookup is disabled; enable it explicitly on the LAB service.")
    if status["missing"]:
        raise UnitySqlError("Unity SQL Lookup prerequisites are missing or invalid: " + ", ".join(status["missing"]) + ".")

    host = str(unity_host or "").strip()
    username = str(environ["UNITY_SQL_LOOKUP_SSH_USER"]).strip()
    password = str(environ["UNITY_SQL_LOOKUP_SSH_PASSWORD"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise UnitySqlError("Configured LAB Unity host is invalid.")

    known_hosts_file = os.path.abspath(os.path.expanduser(str(environ["UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE"]).strip()))
    if not os.path.isfile(known_hosts_file):
        raise UnitySqlError("Configured SSH known-hosts file is unavailable; host-key verification is required.")
    return {
        "host": host,
        "username": username,
        "password": str(password),
        "known_hosts_file": known_hosts_file,
    }


def _execute_ssh_command(config, command, client_factory=None, reject_policy_factory=None):
    if client_factory is None or reject_policy_factory is None:
        try:
            import paramiko
        except ImportError as exc:
            raise UnitySqlError("Paramiko is unavailable on the portal server.") from exc
        client_factory = client_factory or paramiko.SSHClient
        reject_policy_factory = reject_policy_factory or paramiko.RejectPolicy
    client = client_factory()
    try:
        client.load_host_keys(config["known_hosts_file"])
        client.set_missing_host_key_policy(reject_policy_factory())
        client.connect(
            hostname=config["host"],
            username=config["username"],
            password=config["password"],
            look_for_keys=False,
            allow_agent=False,
            timeout=4,
            banner_timeout=4,
            auth_timeout=4,
        )
        _, stdout, stderr = client.exec_command(shlex.quote(command), timeout=SSH_TIMEOUT_SECONDS, get_pty=False)
        channel = stdout.channel
        channel.settimeout(SSH_TIMEOUT_SECONDS)
        output = stdout.read(MAX_OUTPUT_BYTES + 1)
        if len(output) > MAX_OUTPUT_BYTES:
            raise UnitySqlError("Unity CLI output exceeded the safe response limit; narrow the search.")
        stderr.read(65536)
        if channel.recv_exit_status() != 0:
            raise UnitySqlError("Unity SSH/CLI request failed; no incomplete report was saved.")
        return output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output or "")
    except TimeoutError as exc:
        raise UnitySqlError("Unity SSH lookup timed out; no incomplete report was saved.") from exc
    except UnitySqlError:
        raise
    except Exception as exc:
        raise UnitySqlError("Unity SSH authentication or connection failed; verify the LAB credentials and pinned host key.") from exc
    finally:
        client.close()


def lookup_report(number, mode="exact", unity_host="", environ=None, client_factory=None, reject_policy_factory=None):
    commands = command_templates(number, mode)
    config = _ssh_configuration(unity_host, environ)
    if not unity_host or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", str(unity_host).strip()):
        raise ValueError("A verified Unity host label is required.")
    rows = []
    for label, command in commands:
        output = _execute_ssh_command(config, command, client_factory, reject_policy_factory)
        for row in parse_cli_rows(output):
            rows.append(dict(row, query_type=label))

    return {
        "schema_version": 1,
        "host": str(unity_host).strip().lower(),
        "query": re.sub(r"[^0-9]", "", str(number)),
        "mode": mode,
        "rows": rows,
        "match_count": len(rows),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "coverage": [label for label, _ in commands],
        "limitations": LIMITATIONS,
        "retention": RETENTION,
    }


def _report_path(root, host):
    if not host or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", str(host).strip()):
        raise UnitySqlError("A valid Unity host is required for saved lookup data.")
    host_key = str(host).strip().lower()
    return os.path.join(root, hashlib.sha256(host_key.encode("utf-8")).hexdigest() + ".json")


def load_report(root, host):
    path = _report_path(root, host)
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
    except FileNotFoundError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise UnitySqlError("Saved Unity SQL lookup is unreadable; it was not overwritten.") from exc
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != 1
        or report.get("host") != str(host).strip().lower()
        or report.get("mode") not in {"exact", "contains"}
        or not isinstance(report.get("rows"), list)
        or not isinstance(report.get("coverage"), list)
        or not re.fullmatch(r"[0-9]{3,15}", str(report.get("query", "")))
    ):
        raise UnitySqlError("Saved Unity SQL lookup is invalid; it was not overwritten.")
    return report


def save_report(root, report):
    if not isinstance(report, dict) or report.get("schema_version") != 1 or not isinstance(report.get("rows"), list):
        raise UnitySqlError("Unity SQL report is invalid and was not saved.")
    path = _report_path(root, report.get("host", ""))
    os.makedirs(root, exist_ok=True)
    if os.path.exists(path):
        load_report(root, report["host"])
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as handle:
            temp_path = handle.name
            if os.name != "nt":
                os.chmod(temp_path, 0o600)
            json.dump(report, handle, ensure_ascii=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(3):
            try:
                os.replace(temp_path, path)
                temp_path = ""
                break
            except PermissionError:
                if os.name != "nt" or attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
        if os.name != "nt":
            directory = os.open(root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as exc:
        raise UnitySqlError("Unity SQL lookup could not be saved; the previous report is retained.") from exc
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def lookup_queries(number, mode="exact"):
    number = str(number or "").strip()
    if not re.fullmatch(r"[0-9]{3,15}", number):
        raise ValueError("Enter 3-15 digits only; stored dialing prefixes are preserved.")
    if mode not in {"exact", "contains"}:
        raise ValueError("Choose Exact or Contains.")
    def match(field):
        return field + ("='" + number + "'" if mode == "exact" else " like '%" + number + "%'")
    return [
        ("Mailbox caller input", "select first 501 s.displayname as owner_name,s.dtmfaccessid as primary_extension,'TransferNumber' as matched_field,a.transfernumber as matched_number,a.touchtonekey as setting from vw_alternatecontactnumber_subscriber a join vw_subscriberbasic s on s.objectid=a.subscriberobjectid where " + match("a.transfernumber")),
        ("User/handler transfer rule", "select first 501 coalesce(s.displayname,h.displayname) as owner_name,coalesce(s.dtmfaccessid,h.dtmfaccessid) as primary_extension,'Extension' as matched_field,t.extension as matched_number,t.transferoptiontype as setting from vw_transferoptiondisplay t join vw_callhandler h on h.objectid=t.callhandlerobjectid left join vw_subscriberbasic s on s.callhandlerobjectid=h.objectid where " + match("t.extension")),
        ("Mailbox primary extension", "select first 501 s.displayname as owner_name,s.dtmfaccessid as primary_extension,'DtmfAccessId' as matched_field,s.dtmfaccessid as matched_number,'Primary' as setting from vw_subscriberbasic s where " + match("s.dtmfaccessid")),
        ("Handler primary extension", "select first 501 coalesce(s.displayname,h.displayname) as owner_name,coalesce(s.dtmfaccessid,h.dtmfaccessid) as primary_extension,'DtmfAccessId' as matched_field,h.dtmfaccessid as matched_number,'Primary' as setting from vw_callhandler h left join vw_subscriberbasic s on s.callhandlerobjectid=h.objectid where " + match("h.dtmfaccessid")),
    ]


def parse_cli_rows(output):
    lines = output.replace("\r", "").split("\n")
    if any(re.match(r"\s*(?:SQL (?:error|state)|error\s*:|syntax error|permission denied|command failed)", line, re.I) for line in lines):
        raise UnitySqlError("Unity CLI returned an error; lookup is incomplete.")
    for index, line in enumerate(lines):
        if index == 0 or not re.fullmatch(r"\s*-+(?:\s+-+)*\s*", line):
            continue
        spans = list(re.finditer(r"-+", line))
        if len(spans) != len(RESULT_COLUMNS) or tuple(lines[index - 1].split()) != RESULT_COLUMNS:
            continue
        rows = []
        for data in lines[index + 1:]:
            if not data.strip() or data.strip() == "admin:" or data.strip().startswith("admin:run cuc dbquery"):
                continue
            values = [data[span.start():spans[position + 1].start() if position + 1 < len(spans) else None].strip() for position, span in enumerate(spans)]
            values = ["" if value.lower() == "null" else value for value in values]
            if not values[0] or not values[3] or values[2] not in {"TransferNumber", "Extension", "DtmfAccessId"}:
                raise UnitySqlError("Unity CLI output is wrapped or incomplete; it was not treated as empty.")
            rows.append(dict(zip(RESULT_COLUMNS, values)))
        if len(rows) > MAX_ROWS:
            raise UnitySqlError("More than 500 rows match; narrow the search.")
        return rows
    if re.fullmatch(r"\s*(?:No (?:records|rows)(?: found)?|0 rows(?: returned)?)\.?\s*", output, re.I):
        return []
    raise UnitySqlError("Expected Unity SQL result columns were not returned; no-match status is unverified.")


def command_templates(number, mode="exact"):
    return [(label, "run cuc dbquery unitydirdb " + query) for label, query in lookup_queries(number, mode)]
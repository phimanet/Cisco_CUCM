import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
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
        "UNITY_SQL_LOOKUP_LAB_SSH_HOST",
        "UNITY_SQL_LOOKUP_SSH_USER",
        "UNITY_SQL_LOOKUP_SSH_KEY_FILE",
        "UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE",
    )
    missing = [name for name in required if not str(environ.get(name, "")).strip()]
    if enabled and not missing:
        host = str(environ["UNITY_SQL_LOOKUP_LAB_SSH_HOST"]).strip()
        username = str(environ["UNITY_SQL_LOOKUP_SSH_USER"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
            missing.append("UNITY_SQL_LOOKUP_LAB_SSH_HOST (invalid)")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
            missing.append("UNITY_SQL_LOOKUP_SSH_USER (invalid)")
        key_file = os.path.abspath(os.path.expanduser(str(environ["UNITY_SQL_LOOKUP_SSH_KEY_FILE"]).strip()))
        known_hosts_file = os.path.abspath(os.path.expanduser(str(environ["UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE"]).strip()))
        if not os.path.isfile(key_file):
            missing.append("UNITY_SQL_LOOKUP_SSH_KEY_FILE (unavailable)")
        elif os.name != "nt" and os.stat(key_file).st_mode & 0o077:
            missing.append("UNITY_SQL_LOOKUP_SSH_KEY_FILE (permissions must exclude group/other)")
        if not os.path.isfile(known_hosts_file):
            missing.append("UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE (unavailable)")
        if not shutil.which("ssh"):
            missing.append("OpenSSH client")
    return {"enabled": enabled, "configured": enabled and not missing, "missing": missing, "read_only": True}


def _ssh_configuration(environ=None):
    environ = os.environ if environ is None else environ
    status = configuration_status(environ)
    if not status["enabled"]:
        raise UnitySqlError("Unity SQL Lookup is disabled; enable it explicitly on the LAB service.")
    if status["missing"]:
        raise UnitySqlError("Unity SQL Lookup prerequisites are missing or invalid: " + ", ".join(status["missing"]) + ".")

    host = str(environ["UNITY_SQL_LOOKUP_LAB_SSH_HOST"]).strip()
    username = str(environ["UNITY_SQL_LOOKUP_SSH_USER"]).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise UnitySqlError("Configured LAB SSH host is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
        raise UnitySqlError("Configured SSH username is invalid.")

    key_file = os.path.abspath(os.path.expanduser(str(environ["UNITY_SQL_LOOKUP_SSH_KEY_FILE"]).strip()))
    known_hosts_file = os.path.abspath(os.path.expanduser(str(environ["UNITY_SQL_LOOKUP_KNOWN_HOSTS_FILE"]).strip()))
    if not os.path.isfile(key_file):
        raise UnitySqlError("Configured SSH key file is unavailable to the portal service account.")
    if not os.path.isfile(known_hosts_file):
        raise UnitySqlError("Configured SSH known-hosts file is unavailable; host-key verification is required.")
    return {"host": host, "username": username, "key_file": key_file, "known_hosts_file": known_hosts_file}


def _ssh_argv(config, command):
    ssh = shutil.which("ssh")
    if not ssh:
        raise UnitySqlError("OpenSSH client is unavailable on the portal server.")
    return [
        ssh,
        "-T",
        "-i", config["key_file"],
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PreferredAuthentications=publickey",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + config["known_hosts_file"],
        "-o", "ConnectTimeout=4",
        "-o", "ServerAliveInterval=4",
        "-o", "ServerAliveCountMax=2",
        "-o", "LogLevel=ERROR",
        config["username"] + "@" + config["host"],
        shlex.quote(command),
    ]


def lookup_report(number, mode="exact", unity_host="", runner=None, environ=None):
    commands = command_templates(number, mode)
    config = _ssh_configuration(environ)
    if not unity_host or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", str(unity_host).strip()):
        raise ValueError("A verified Unity host label is required.")
    runner = runner or subprocess.run
    rows = []
    for label, command in commands:
        try:
            result = runner(
                _ssh_argv(config, command),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=SSH_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise UnitySqlError("Unity SSH lookup timed out; no incomplete report was saved.") from exc
        except OSError as exc:
            raise UnitySqlError("Unity SSH lookup could not start; verify OpenSSH and service-account access.") from exc
        output = result.stdout or ""
        if len(output.encode("utf-8", errors="replace")) > MAX_OUTPUT_BYTES:
            raise UnitySqlError("Unity CLI output exceeded the safe response limit; narrow the search.")
        if result.returncode != 0:
            raise UnitySqlError("Unity SSH/CLI request failed; no incomplete report was saved.")
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
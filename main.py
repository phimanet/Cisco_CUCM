import csv
import datetime
import io
import os
import re
import smtplib
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from email.message import EmailMessage
from zoneinfo import ZoneInfo

import requests
import urllib3
from fastapi import FastAPI, Form, UploadFile, File, Query, Request
from fastapi.responses import HTMLResponse, Response, JSONResponse, RedirectResponse
from html import escape
from requests.auth import HTTPBasicAuth
from uuid import uuid4

from toolkit.enduser import export_endusers_all_fields
from toolkit.directory_number import export_directory_numbers
from toolkit.add_directory_number import add_directory_numbers_from_csv
from toolkit.build_user_csf_phone import build_user_csf_phone_from_template, lookup_user_jabber_status
from toolkit.decommission_user_csf_voicemail import decommission_user_csf_voicemail
from toolkit.reset_unity_voicemail_pin import reset_unity_voicemail_pin
from toolkit.update_ad_phone_only import update_ad_phone_fields_only
from toolkit.add_secondary_devices import (
  add_secondary_tct_device,
  add_secondary_bot_device,
  add_secondary_strike_devices,
  delete_secondary_mobile_devices,
)
from toolkit.called_name_change import run_called_name_change
from toolkit.edit_line_group_members import edit_line_group_members, search_line_groups
from toolkit.extract_rpo_phones import extract_rpo_phones
from toolkit.person_lookup import search_persons_by_name
from toolkit.extension_lookup import lookup_extension_owner, check_user_devices
from toolkit.translation_pattern_lookup import lookup_translation_patterns, build_translation_pattern_template
from toolkit.create_teams_telephony_user import create_teams_telephony_user
from toolkit.remove_teams_telephony_user import (
  lookup_teams_telephony_removal_candidate,
  remove_teams_telephony_user,
)

app = FastAPI(title="Cisco Voice Server Automation Site - Restricted Access")
JOB_OUTPUTS = {}
AUTH_SESSIONS = {}
SESSION_COOKIE_NAME = "cucm_web_session"
SESSION_IDLE_TIMEOUT_SECONDS = 8 * 60 * 60
APP_START_EPOCH = time.time()
PROD_CUCM_HOST = "lascucmpp01.ahs.int"
LAB_CUCM_HOST = "lascucmpl01.ahs.int"
PROD_UNITY_HOST = "SANCUTYP01.ahs.int"
LAB_UNITY_HOST = "lascutypl01.ahs.int"
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp1.ahs.int").strip() or "smtp1.ahs.int"
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS", "20"))
SMTP_USE_STARTTLS = (os.getenv("SMTP_USE_STARTTLS", "false") or "false").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
SMTP_DEFAULT_FROM = (os.getenv("SMTP_DEFAULT_FROM", "") or "").strip()
MOBILE_JABBER_EMAIL_FROM = "noreply@amnhealthcare.com"
MOBILE_JABBER_EMAIL_SUBJECT = "Jabber on iPhone or Android - Ready to install"
MOBILE_JABBER_EMAIL_BODY = (
  "Jabber for mobile phones is ready for use.\n\n"
  "You must delete the app on the iPhone/Android first if you have it already installed.\n\n"
  "To setup Jabber on your mobile phone:\n\n"
  "1. Download Cisco Jabber on your mobile phone.\n"
  "2. Go thru the questions and accept Jabber to use the microphone.\n"
  "3. Enter in your AMN Email address.\n"
  "4. Enter in your AMN password.\n"
  "5. If it balks at an invalid certificate, this is OK. Accept or press OK.\n"
  "6. You should now be logged in."
)
CSF_JABBER_EMAIL_FROM = (os.getenv("CSF_JABBER_EMAIL_FROM", MOBILE_JABBER_EMAIL_FROM) or MOBILE_JABBER_EMAIL_FROM).strip()
CSF_JABBER_TRAINING_URL = (
  "https://amnhealthcare.sharepoint.com/teams/AMNITTrainingContent-tm/_layouts/15/stream.aspx?id=%2Fteams%2FAMNITTrainingContent%2Dtm%2FShared%20Documents%2FGeneral%2FWatch%20and%20Learn%20Cisco%20Jabber%20Softphone%2012%2E9%2Emp4&referrer=StreamWebApp%2EWeb&referrerScenario=AddressBarCopied%2Eview%2E973e7ace%2Dcbde%2D4892%2D8252%2Dd3edcfda9374"
)
AUDIT_LOG_LOCK = threading.Lock()
AUDIT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
AUDIT_TIMEZONE = (os.getenv("AUDIT_TIMEZONE", "America/Los_Angeles") or "America/Los_Angeles").strip()
ADMIN_USERS = {
  (u or "").strip().lower()
  for u in (os.getenv("ADMIN_USERS", "") or "").split(",")
  if (u or "").strip()
}
AUDIT_RETENTION_DAYS = 365
AUDIT_FIELDS = [
  "timestamp",
  "action",
  "cucm_host",
  "operator",
  "target",
  "account",
  "extension_added",
  "extension_deleted",
  "output_filename",
  "inline_mode",
]
AUDIT_LOG_PATH = os.path.join(
  os.path.dirname(os.path.abspath(__file__)),
  "logs",
  "audit_trail.csv",
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _prune_auth_sessions_locked(now_epoch: float):
  expired = [
    sid
    for sid, data in AUTH_SESSIONS.items()
    if (now_epoch - float(data.get("last_seen", 0))) > SESSION_IDLE_TIMEOUT_SECONDS
  ]
  for sid in expired:
    AUTH_SESSIONS.pop(sid, None)


def _create_auth_session(cucm_host: str, username: str) -> str:
  session_id = str(uuid4())
  now_epoch = time.time()
  AUTH_SESSIONS[session_id] = {
    "cucm_host": (cucm_host or "").strip(),
    "username": (username or "").strip(),
    "unity_user": "",
    "created_at": now_epoch,
    "last_seen": now_epoch,
  }
  return session_id


def _get_auth_session(request: Request):
  session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
  if not session_id:
    return None

  now_epoch = time.time()
  _prune_auth_sessions_locked(now_epoch)
  session = AUTH_SESSIONS.get(session_id)
  if not session:
    return None

  session["last_seen"] = now_epoch
  return session


def _normalize_username(username: str) -> str:
  user = (username or "").strip().lower()
  if not user:
    return ""
  if "@" in user:
    user = user.split("@", 1)[0].strip()
  return user


def _is_admin_user(username: str) -> bool:
  normalized = _normalize_username(username)
  if not normalized:
    return False

  # Always allow known admin prefixes.
  if normalized.startswith("phimane") or normalized.startswith("laura") or normalized.startswith("jerald"):
    return True

  # Backward-compatible default: if allowlist is not configured, do not restrict.
  if not ADMIN_USERS:
    return True

  return normalized in ADMIN_USERS


def _update_cached_credentials(
  request: Request,
  cucm_host: str = "",
  cucm_user: str = "",
  unity_user: str = "",
):
  session = _get_auth_session(request)
  if not session:
    return

  if (cucm_host or "").strip():
    session["cucm_host"] = cucm_host.strip()
  if (cucm_user or "").strip():
    session["username"] = cucm_user.strip()
  if (unity_user or "").strip():
    session["unity_user"] = unity_user.strip()


def _resolve_cucm_credentials(request: Request, cucm_host: str, cucm_user: str, cucm_pass: str):
  session = _get_auth_session(request)
  if not session:
    raise RuntimeError("Authentication required.")

  resolved_host = (cucm_host or "").strip() or session.get("cucm_host", "")
  resolved_user = (cucm_user or "").strip() or session.get("username", "")
  resolved_pass = cucm_pass

  if not resolved_host or not resolved_user or not resolved_pass:
    raise RuntimeError("Missing CUCM credentials. Enter username/password for this action.")

  return resolved_host, resolved_user, resolved_pass


def _resolve_unity_credentials(request: Request, unity_user: str, unity_pass: str):
  session = _get_auth_session(request)
  if not session:
    raise RuntimeError("Authentication required.")

  resolved_user = (unity_user or "").strip() or session.get("unity_user", "") or session.get("username", "")
  resolved_pass = unity_pass

  if not resolved_user or not resolved_pass:
    raise RuntimeError("Missing Unity credentials. Enter Unity admin username/password for this action.")

  return resolved_user, resolved_pass


def _validate_cucm_login(cucm_host: str, cucm_user: str, cucm_pass: str):
  soap_xml = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getCCMVersion/>
  </soapenv:Body>
</soapenv:Envelope>"""

  url = f"https://{cucm_host}:8443/axl/"
  try:
    response = requests.post(
      url,
      data=soap_xml.encode("utf-8"),
      headers={"Content-Type": "text/xml"},
      auth=HTTPBasicAuth(cucm_user, cucm_pass),
      timeout=20,
      verify=False,
    )
  except Exception as exc:
    return False, f"Could not reach CUCM AXL endpoint: {exc}"

  if response.status_code == 200:
    return True, "Login successful"

  return False, f"Login failed (HTTP {response.status_code}). Verify host/username/password."


def _is_lab_host(cucm_host: str):
  return (cucm_host or "").strip().lower() == LAB_CUCM_HOST.lower()


def _get_environment_label(cucm_host: str):
  if _is_lab_host(cucm_host):
    return "LAB Voice Servers - TESTING ONLY", "env-banner-lab"
  return "Production Voice Servers", "env-banner-prod"


def _get_unity_server_for_session(request: Request):
  session = _get_auth_session(request)
  if not session:
    raise RuntimeError("Authentication required.")

  cucm_host = session.get("cucm_host", "")
  if _is_lab_host(cucm_host):
    return LAB_UNITY_HOST
  return PROD_UNITY_HOST


def _is_public_path(path: str):
  return path in {"/", "/login", "/genesys-admin", "/healthz"}


def _wants_json_response(request: Request) -> bool:
  requested_with = (request.headers.get("x-requested-with", "") or "").lower()
  accept_header = (request.headers.get("accept", "") or "").lower()
  inline_flag = (request.query_params.get("inline", "") or "").strip().lower()

  if requested_with == "xmlhttprequest":
    return True
  if "application/json" in accept_header:
    return True
  if inline_flag in {"1", "true", "yes", "on"}:
    return True
  if request.url.path in {
    "/line-groups/search",
    "/audit-trail/stats",
    "/healthz",
    "/lookup/person",
    "/lookup/extension",
    "/lookup/translation-pattern",
    "/bulk/lookup/person",
    "/bulk/lookup/extension",
    "/check/user-devices",
  }:
    return True
  return False


def _render_error_page(title: str, message: str, status_code: int) -> HTMLResponse:
  safe_title = escape(title or "Request Error")
  safe_message = escape(message or "Unexpected error")
  html = f"""
<html>
  <head>
    <title>{safe_title}</title>
    <style>
      body {{
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        margin: 0;
        background: linear-gradient(180deg, #f7fbff 0%, #edf5fc 100%);
        color: #12304a;
      }}

      .card {{
        max-width: 880px;
        margin: 48px auto;
        background: #fff;
        border: 1px solid #c8dbee;
        border-radius: 12px;
        padding: 22px;
        box-shadow: 0 8px 20px rgba(0, 47, 108, 0.08);
      }}

      h2 {{
        margin-top: 0;
        color: #002f6c;
      }}

      p {{
        line-height: 1.45;
      }}

      .meta {{
        color: #355978;
        font-size: 13px;
      }}

      a {{
        color: #005eb8;
        font-weight: 700;
      }}
    </style>
  </head>
  <body>
    <section class="card">
      <h2>{safe_title}</h2>
      <p>{safe_message}</p>
      <p class="meta">Status: {status_code}</p>
      <p><a href="/menu">Back to Menu</a> | <a href="/">Back to Landing Page</a></p>
    </section>
  </body>
</html>
"""
  return HTMLResponse(content=html, status_code=status_code)


@app.exception_handler(RuntimeError)
async def runtime_error_handler(request: Request, exc: RuntimeError):
  message = str(exc) or "Request validation failed."
  status_code = 401 if "authentication required" in message.lower() else 400

  if _wants_json_response(request):
    return JSONResponse(
      {
        "ok": False,
        "error": {
          "type": "runtime_error",
          "message": message,
          "path": request.url.path,
          "status": status_code,
        },
      },
      status_code=status_code,
    )

  return _render_error_page("Request Error", message, status_code)


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
  message = "Unexpected server error. Retry the request and contact support if it continues."

  if _wants_json_response(request):
    return JSONResponse(
      {
        "ok": False,
        "error": {
          "type": "internal_error",
          "message": message,
          "path": request.url.path,
          "status": 500,
        },
      },
      status_code=500,
    )

  return _render_error_page("Server Error", message, 500)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
  if _is_public_path(request.url.path):
    return await call_next(request)

  session = _get_auth_session(request)
  if not session:
    return RedirectResponse(url="/", status_code=303)

  request.state.auth_session = session
  return await call_next(request)


def _ensure_audit_log():
  os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
  if os.path.exists(AUDIT_LOG_PATH):
    return

  with open(AUDIT_LOG_PATH, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow(AUDIT_FIELDS)


def _prune_audit_log_locked():
  _ensure_audit_log()

  with open(AUDIT_LOG_PATH, "r", newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    rows = list(reader)

  cutoff = _audit_now() - datetime.timedelta(days=AUDIT_RETENTION_DAYS)
  kept_rows = []
  for row in rows:
    ts_text = (row.get("timestamp") or "").strip()
    if not ts_text:
      continue

    try:
      ts = datetime.datetime.strptime(ts_text, AUDIT_TIMESTAMP_FORMAT)
    except ValueError:
      # Keep malformed legacy rows to avoid destructive data loss.
      kept_rows.append(row)
      continue

    if ts >= cutoff:
      kept_rows.append(row)

  with open(AUDIT_LOG_PATH, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=AUDIT_FIELDS)
    writer.writeheader()
    for row in kept_rows:
      writer.writerow({field: row.get(field, "") for field in AUDIT_FIELDS})


def _append_audit_event(
  action: str,
  cucm_host: str,
  operator: str,
  target: str,
  output_filename: str,
  inline_mode: bool,
  account: str = "",
  extension_added: str = "",
  extension_deleted: str = "",
):
  row = [
    _audit_now().strftime(AUDIT_TIMESTAMP_FORMAT),
    action,
    cucm_host,
    operator,
    target,
    account,
    extension_added,
    extension_deleted,
    output_filename,
    str(bool(inline_mode)).lower(),
  ]

  with AUDIT_LOG_LOCK:
    _ensure_audit_log()
    _prune_audit_log_locked()
    with open(AUDIT_LOG_PATH, "a", newline="", encoding="utf-8") as handle:
      writer = csv.writer(handle)
      writer.writerow(row)


def _audit_now() -> datetime.datetime:
  try:
    return datetime.datetime.now(ZoneInfo(AUDIT_TIMEZONE)).replace(tzinfo=None)
  except Exception:
    # Fall back to server local time if timezone configuration is invalid.
    return datetime.datetime.now()


def _to_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    return str(data).encode("utf-8")


def _send_smtp_email(
    sender: str,
    recipients: list[str],
    subject: str,
    body: str,
    smtp_user: str = "",
    smtp_pass: str = "",
    smtp_port: int | None = None,
    use_starttls: bool | None = None,
  ):
    if not sender:
      raise RuntimeError("Sender email is required.")

    clean_recipients = [r.strip() for r in recipients if (r or "").strip()]
    if not clean_recipients:
      raise RuntimeError("At least one recipient email is required.")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(clean_recipients)
    message["Subject"] = subject or "CUCM Web SMTP Test"
    message.set_content(body or "SMTP test message from CUCM web portal.")

    resolved_port = smtp_port if smtp_port is not None else SMTP_PORT
    resolved_starttls = SMTP_USE_STARTTLS if use_starttls is None else use_starttls

    with smtplib.SMTP(SMTP_SERVER, resolved_port, timeout=SMTP_TIMEOUT_SECONDS) as server:
      server.ehlo()
      if resolved_starttls:
        server.starttls(context=ssl.create_default_context())
        server.ehlo()

      if (smtp_user or "").strip() or (smtp_pass or "").strip():
        server.login((smtp_user or "").strip(), smtp_pass or "")

      server.send_message(message)


def _store_job_output(csv_data: bytes, filename: str) -> str:
    job_id = str(uuid4())
    JOB_OUTPUTS[job_id] = {"data": csv_data, "filename": filename}

    # Keep an in-memory cap so older outputs naturally roll off.
    if len(JOB_OUTPUTS) > 100:
        oldest_key = next(iter(JOB_OUTPUTS))
        JOB_OUTPUTS.pop(oldest_key, None)

    return job_id


def _prepare_job_output(csv_data, filename: str) -> dict:
    csv_bytes = _to_bytes(csv_data)
    job_id = _store_job_output(csv_bytes, filename)
    return {
        "job_id": job_id,
        "filename": filename,
        "output_text": csv_bytes.decode("utf-8", errors="replace"),
    }


def _pick_column(fieldnames: list[str], candidates: list[str]) -> str:
    normalized = {name.strip().lower(): name for name in fieldnames if name}
    for candidate in candidates:
      match = normalized.get(candidate)
      if match:
        return match
    return ""


def _parse_bulk_person_inputs(csv_text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    stream = io.StringIO(csv_text or "")
    reader = csv.DictReader(stream)

    if reader.fieldnames:
      last_col = _pick_column(
        reader.fieldnames,
        ["last_name", "lastname", "last", "lname", "surname"],
      )
      first_col = _pick_column(
        reader.fieldnames,
        ["first_name", "firstname", "first", "fname", "givenname"],
      )

      if not last_col and reader.fieldnames:
        last_col = reader.fieldnames[0]

      for row in reader:
        last_name = (row.get(last_col, "") if last_col else "").strip()
        first_name = (row.get(first_col, "") if first_col else "").strip()
        if last_name:
          rows.append((last_name, first_name))

      return rows

    # Fallback for CSV with no header: first column = last name, second = first name (optional)
    stream.seek(0)
    plain_reader = csv.reader(stream)
    for values in plain_reader:
      if not values:
        continue
      last_name = (values[0] or "").strip()
      first_name = (values[1] or "").strip() if len(values) > 1 else ""
      if last_name:
        rows.append((last_name, first_name))

    return rows


def _parse_bulk_extension_inputs(csv_text: str) -> list[str]:
    values: list[str] = []
    stream = io.StringIO(csv_text or "")
    reader = csv.DictReader(stream)

    if reader.fieldnames:
      pattern_col = _pick_column(
        reader.fieldnames,
        ["pattern", "extension", "dn", "directory_number", "number"],
      )
      if not pattern_col and reader.fieldnames:
        pattern_col = reader.fieldnames[0]

      for row in reader:
        pattern = (row.get(pattern_col, "") if pattern_col else "").strip()
        if pattern:
          values.append(pattern)

      return values

    # Fallback for CSV with no header: first column = pattern
    stream.seek(0)
    plain_reader = csv.reader(stream)
    for row in plain_reader:
      if not row:
        continue
      pattern = (row[0] or "").strip()
      if pattern:
        values.append(pattern)

    return values


def _extract_added_dn_from_build_output(csv_data) -> str:
    csv_text = _to_bytes(csv_data).decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(csv_text))

    # Prefer the explicit DN selection row, then fall back to other success rows.
    for row in reader:
        if len(row) < 3:
            continue
        step = (row[0] or "").strip()
        status = (row[1] or "").strip().lower()
        details = (row[2] or "").strip()
        if step == "Select DN" and status == "success":
            match = re.search(r"\b(\d{4,})\b", details)
            if match:
                return match.group(1)

    reader = csv.reader(io.StringIO(csv_text))
    for row in reader:
        if len(row) < 3:
            continue
        step = (row[0] or "").strip()
        status = (row[1] or "").strip().lower()
        details = (row[2] or "").strip()
        if step in {"Add Phone", "Update User", "Unity Voicemail"} and status == "success":
            match = re.search(r"\b(\d{4,})\b", details)
            if match:
                return match.group(1)

    return ""


def _extract_deleted_dns_from_offboard_output(csv_data) -> list[str]:
    csv_text = _to_bytes(csv_data).decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(csv_text))
    deleted_dns = []

    for row in reader:
        if len(row) < 3:
            continue
        step = (row[0] or "").strip()
        status = (row[1] or "").strip().lower()
        details = (row[2] or "").strip()
        if step != "Update Line Inactive" or status != "success":
            continue

        # Expected format: "Marked <pattern>/<partition> inactive and reusable"
        match = re.search(r"Marked\s+([^/\s]+)\/", details)
        if match:
            dn = match.group(1)
            if dn not in deleted_dns:
                deleted_dns.append(dn)

    return deleted_dns


def _csv_has_success_step(csv_data, step_names: set[str]) -> bool:
    csv_text = _to_bytes(csv_data).decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(csv_text))
    target_steps = {s.strip().lower() for s in step_names if (s or "").strip()}

    for row in reader:
      if len(row) < 2:
        continue
      step = (row[0] or "").strip().lower()
      status = (row[1] or "").strip().lower()
      if step in target_steps and status == "success":
        return True

    return False


def _extract_mobile_shared_dn_from_output(csv_data) -> str:
  csv_text = _to_bytes(csv_data).decode("utf-8", errors="replace")
  reader = csv.reader(io.StringIO(csv_text))

  for row in reader:
    if len(row) < 3:
      continue
    step = (row[0] or "").strip()
    status = (row[1] or "").strip().lower()
    details = (row[2] or "").strip()
    if step == "Resolve DN" and status == "success":
      match = re.search(r"\b(\d{4,})\b", details)
      if match:
        return match.group(1)

  return ""


def _append_result_row(csv_data, step: str, status: str, details: str) -> bytes:
    csv_text = _to_bytes(csv_data).decode("utf-8", errors="replace")
    output = io.StringIO()
    output.write(csv_text)
    if not csv_text.endswith("\n"):
      output.write("\n")
    writer = csv.writer(output)
    writer.writerow([step, status, details])
    return output.getvalue().encode("utf-8")


def _lookup_user_contact(cucm_host: str, cucm_user: str, cucm_pass: str, target_user: str) -> tuple[str, str]:
    clean_target = (target_user or "").strip()
    if not clean_target:
      return "", ""

    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getUser>
      <userid>{escape(clean_target)}</userid>
    </axl:getUser>
  </soapenv:Body>
</soapenv:Envelope>"""

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    response = session.post(
      f"https://{cucm_host}:8443/axl/",
      data=soap.encode("utf-8"),
      headers={"Content-Type": "text/xml"},
      timeout=60,
    )
    if response.status_code != 200:
      raise RuntimeError(f"getUser failed HTTP {response.status_code}")

    root = ET.fromstring(response.text)
    user_node = None
    for elem in root.iter():
      if elem.tag.split("}")[-1] == "user":
        user_node = elem
        break

    if user_node is None:
      raise RuntimeError("Unable to read user details from CUCM response")

    values = {}
    for child in list(user_node):
      key = child.tag.split("}")[-1]
      values[key] = (child.text or "").strip()

    full_name = " ".join(
      part for part in [values.get("firstName", ""), values.get("lastName", "")] if part
    ).strip()
    display_name = full_name or values.get("displayName", "") or values.get("userid", clean_target)
    return values.get("mailid", ""), display_name


def _send_mobile_jabber_ready_email_if_built(
  cucm_host: str,
  cucm_user: str,
  cucm_pass: str,
  target_user: str,
  csv_data,
  created_steps: set[str],
) -> tuple[str, str]:
    if not _csv_has_success_step(csv_data, created_steps):
      return "Skipped", "No new mobile Jabber device was created; email not sent"

    recipient, display_name = _lookup_user_contact(cucm_host, cucm_user, cucm_pass, target_user)
    recipient = (recipient or "").strip()
    if not recipient:
      return "Failed", "Target user does not have a CUCM mailid; email not sent"

    phone_number = _extract_mobile_shared_dn_from_output(csv_data)
    return _send_mobile_jabber_ready_email(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=target_user,
      phone_number=phone_number,
      recipient=recipient,
      display_name=display_name,
    )


def _compose_mobile_jabber_email_body(display_name: str, phone_number: str) -> str:
    phone_text = _format_notification_phone(phone_number) or "XXX-XXX-XXXX"
    second_sentence = (
      "Jabber mobile has the uses the same telephone number as Jabber on your laptop. "
      f"Your Jabber telephone number is {phone_text}."
    )
    base_body = MOBILE_JABBER_EMAIL_BODY
    lead_text = "Jabber for mobile phones is ready for use."
    if lead_text in base_body:
      base_body = base_body.replace(lead_text, f"{lead_text} {second_sentence}", 1)
    else:
      base_body = f"{lead_text} {second_sentence}\n\n{base_body}"
    return f"Hello {display_name},\n\n{base_body}"


def _send_mobile_jabber_ready_email(
  cucm_host: str,
  cucm_user: str,
  cucm_pass: str,
  target_user: str,
  phone_number: str,
  recipient: str = "",
  display_name: str = "",
) -> tuple[str, str]:
    resolved_recipient = (recipient or "").strip()
    resolved_display_name = (display_name or "").strip()
    if not resolved_recipient or not resolved_display_name:
      resolved_recipient, resolved_display_name = _lookup_user_contact(cucm_host, cucm_user, cucm_pass, target_user)
      resolved_recipient = (resolved_recipient or "").strip()
      resolved_display_name = (resolved_display_name or "").strip()
    if not resolved_recipient:
      return "Failed", "Target user does not have a CUCM mailid; email not sent"

    body = _compose_mobile_jabber_email_body(resolved_display_name, phone_number)
    _send_smtp_email(
      sender=MOBILE_JABBER_EMAIL_FROM,
      recipients=[resolved_recipient],
      subject=MOBILE_JABBER_EMAIL_SUBJECT,
      body=body,
      smtp_port=SMTP_PORT,
      use_starttls=SMTP_USE_STARTTLS,
    )

    return "Success", f"Notification sent to {resolved_recipient} via {SMTP_SERVER}:{SMTP_PORT}"


def _format_notification_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if len(digits) == 11 and digits.startswith("1"):
      digits = digits[1:]
    if len(digits) == 10:
      return f"{digits[0:3]}-{digits[3:6]}-{digits[6:10]}"
    return (value or "").strip() or digits


def _send_csf_jabber_ready_email_if_created(
  cucm_host: str,
  cucm_user: str,
  cucm_pass: str,
  target_user: str,
  added_dn: str,
  new_build: bool = False,
) -> tuple[str, str]:
    number = (added_dn or "").strip()
    if not number:
      return "Skipped", "No new CSF Jabber number was assigned; email not sent"

    recipient, _display_name = _lookup_user_contact(cucm_host, cucm_user, cucm_pass, target_user)
    recipient = (recipient or "").strip()
    if not recipient:
      return "Failed", "Target user does not have a CUCM mailid; email not sent"

    phone_text = _format_notification_phone(number)
    subject = f"Cisco Jabber is ready for use - telephone number {phone_text} assigned"
    if new_build:
      body = (
        f"Cisco Jabber has been created, and ready for your use. Telephone number {phone_text} has been assigned to you.\n\n"
        "Your new voicemail box PIN number is 56219#.\n\n"
        "Please click on the link here for the video training for the use of Cisco Jabber.\n"
        f"{CSF_JABBER_TRAINING_URL}"
      )
    else:
      body = (
        f"Cisco Jabber has been created, and ready for your use. Telephone number {phone_text} has been assigned to you.\n\n"
        "Please click on the link here for the video training for the use of Cisco Jabber.\n"
        f"{CSF_JABBER_TRAINING_URL}"
      )

    _send_smtp_email(
      sender=CSF_JABBER_EMAIL_FROM,
      recipients=[recipient],
      subject=subject,
      body=body,
      smtp_port=SMTP_PORT,
      use_starttls=SMTP_USE_STARTTLS,
    )

    return "Success", f"Notification sent to {recipient} for number {phone_text} via {SMTP_SERVER}:{SMTP_PORT}"


def _extract_account_from_audit_target(target_text: str) -> str:
    text = (target_text or "").strip()
    match = re.search(r"(?:^|;)account=([^;]+)", text, re.IGNORECASE)
    if match:
      return (match.group(1) or "").strip()
    return text


def _find_latest_rebuild_dn_from_audit(account: str) -> str:
    account_clean = (account or "").strip().lower()
    if not account_clean:
      return ""

    with AUDIT_LOG_LOCK:
      _ensure_audit_log()
      _prune_audit_log_locked()
      with open(AUDIT_LOG_PATH, "r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    for row in reversed(rows):
      if (row.get("action") or "").strip() != "offboard_user_option_10":
        continue

      row_account = (row.get("account") or "").strip()
      if not row_account:
        row_account = _extract_account_from_audit_target(row.get("target", ""))
      if row_account.lower() != account_clean:
        continue

      deleted = (row.get("extension_deleted") or "").strip()
      if not deleted:
        target_text = (row.get("target") or "").strip()
        match = re.search(r"(?:^|;)dn_deleted=([^;]+)", target_text, re.IGNORECASE)
        if match:
          deleted = (match.group(1) or "").strip()

      if not deleted or deleted.lower() == "none":
        continue

      for candidate in re.split(r"[|,\s]+", deleted):
        dn = (candidate or "").strip()
        if re.fullmatch(r"\d{4,}", dn):
          return dn

    return ""


def _render_job_result(title: str, csv_data, filename: str, back_url: str = "/menu") -> HTMLResponse:
    job_output = _prepare_job_output(csv_data, filename)
    job_id = job_output["job_id"]
    output_text = escape(job_output["output_text"])

    html = f"""
<html>
  <head>
    <title>{escape(title)} - Job Output</title>
    <style>
      :root {{
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-sky: #eaf4ff;
        --amn-text: #12304a;
        --amn-border: #c8dbee;
      }}

      body {{
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        margin: 0;
        background: linear-gradient(180deg, #f7fbff 0%, #edf5fc 100%);
        color: var(--amn-text);
      }}

      .topbar {{
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 24px;
        background: linear-gradient(90deg, var(--amn-navy), var(--amn-blue));
        color: #fff;
        box-shadow: 0 2px 12px rgba(0, 47, 108, 0.25);
      }}

      .logo {{
        height: 28px;
        width: auto;
        border-radius: 4px;
        background: #fff;
        padding: 3px;
      }}

      .brand-fallback {{
        font-weight: 700;
        letter-spacing: 0.2px;
      }}

      .content {{
        max-width: 1280px;
        margin: 22px auto;
        padding: 0 18px 26px 18px;
      }}

      .panel {{
        background: #fff;
        border: 1px solid var(--amn-border);
        border-radius: 12px;
        padding: 18px;
        box-shadow: 0 8px 20px rgba(0, 47, 108, 0.08);
      }}

      a {{ color: var(--amn-blue); }}

      textarea {{
        width: 100%;
        height: 420px;
        font-family: Consolas, "Courier New", monospace;
        border: 1px solid var(--amn-border);
        border-radius: 8px;
        padding: 10px;
        background: var(--amn-sky);
        color: #0f2940;
      }}
    </style>
  </head>
  <body>
    <header class="topbar">
      <span class="brand-fallback">AMN Healthcare</span>
      <strong>Voice Operations Portal</strong>
    </header>

    <main class="content">
      <section class="panel">
        <h2>{escape(title)} - Job Output</h2>
        <p><a href="{back_url}">Back to Menu</a></p>
        <p>
          <a href="/download/job-output/{job_id}" style="font-weight:bold;">
            Download CSV Output
          </a>
        </p>
        <p>Output Preview:</p>
        <textarea readonly>{output_text}</textarea>
      </section>
    </main>
  </body>
</html>
"""
    return HTMLResponse(html)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    session = _get_auth_session(request)
    if session:
      return RedirectResponse(url="/menu", status_code=303)

    return """
<html>
  <head>
    <title>Cisco Voice Administration Page</title>
    <style>
      :root {
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-sky: #eaf4ff;
        --amn-text: #12304a;
      }

      body {
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        margin: 0;
        background: linear-gradient(180deg, #f7fbff 0%, #edf5fc 100%);
        color: var(--amn-text);
      }

      .topbar {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 24px;
        background: linear-gradient(90deg, var(--amn-navy), var(--amn-blue));
        color: #fff;
      }

      .logo {
        height: 28px;
        width: auto;
        border-radius: 4px;
        background: #fff;
        padding: 3px;
      }

      .brand-fallback {
        font-weight: 700;
        letter-spacing: 0.2px;
      }

      .hero {
        max-width: 900px;
        margin: 48px auto;
        background: #fff;
        border: 1px solid #c8dbee;
        border-radius: 14px;
        padding: 28px;
        box-shadow: 0 8px 20px rgba(0, 47, 108, 0.08);
      }

      a {
        color: var(--amn-blue);
        font-weight: 700;
      }

      input,
      select,
      button {
        border-radius: 8px;
        border: 1px solid #c8dbee;
      }

      input,
      select {
        min-height: 34px;
        padding: 6px 8px;
        width: min(520px, 100%);
      }

      button {
        background: var(--amn-blue);
        color: #fff;
        border: none;
        padding: 10px 14px;
        font-weight: 600;
        cursor: pointer;
      }

      button:hover {
        background: #004f9e;
      }

      .action-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
      }

      .env-action-pill {
        display: inline-block;
        padding: 10px 12px;
        border-radius: 8px;
        font-size: 12px;
        font-weight: 800;
        border: 1px solid var(--amn-border);
      }

      .env-action-pill.env-banner-prod {
        color: #083252;
        background: #d8ecff;
        border-color: #8bb9e2;
      }

      .env-action-pill.env-banner-lab {
        color: #5c2700;
        background: #ffe6cc;
        border-color: #f7b267;
      }

      .login-note {
        color: #244e78;
        font-size: 13px;
      }

      .offboard-h3 {
        color: #b00020;
        font-weight: 900;
        letter-spacing: 0.2px;
        text-transform: uppercase;
      }

      .offboard-form .offboard-danger-btn {
        background: #b00020;
        border: 2px solid #7a0015;
        color: #ffffff;
        font-weight: 800;
        box-shadow: 0 0 0 2px rgba(176, 0, 32, 0.15);
      }

      .offboard-form .offboard-danger-btn:hover {
        background: #7a0015;
      }
    </style>
  </head>
  <body>
    <header class="topbar">
      <span class="brand-fallback">AMN Healthcare</span>
      <strong>Voice Operations Portal</strong>
    </header>

    <section class="hero">
      <h1>Cisco Voice Administration Page</h1>
      <p>
        Welcome to the Cisco Voice administration portal.
        Use this site to run common CUCM automation and reporting tasks.
      </p>

      <h3>Log In</h3>
      <form action="/login" method="post">
        Cisco Callmanager Environment:<br>
        <select name="cucm_host">
          <option value="lascucmpp01.ahs.int" selected>PRODUCTION CUCM</option>
          <option value="lascucmpl01.ahs.int">LAB CUCM</option>
        </select><br><br>

        Cisco Callmanager Username:<br>
        <input name="cucm_user" required><br><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        <button type="submit">Log In</button>
      </form>
      <p class="login-note">
        You must log in before opening Menu Options.
      </p>

      <hr>
      <h3>Other Admin Portals</h3>
      <p>
        Need Genesys tools? Open the separate placeholder page here:
        <a href="/genesys-admin">Genesys Admin</a>
      </p>
    </section>
  </body>
</html>
"""


@app.get("/genesys-admin", response_class=HTMLResponse)
def genesys_admin_placeholder():
  return """
<html>
  <head>
    <title>Genesys Admin - Placeholder</title>
    <style>
      :root {
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-sky: #eaf4ff;
        --amn-ice: #f6fbff;
        --amn-mist: #dbeaf7;
        --amn-gold: #c68a12;
        --amn-text: #12304a;
        --amn-text-soft: #4e6a84;
        --amn-border: #c8dbee;
        --amn-panel-border: rgba(0, 47, 108, 0.12);
        --amn-shadow: 0 18px 40px rgba(0, 47, 108, 0.12);
      }

      body {
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        margin: 0;
        background:
          radial-gradient(circle at top left, rgba(0, 94, 184, 0.18), transparent 26%),
          radial-gradient(circle at top right, rgba(198, 138, 18, 0.16), transparent 22%),
          linear-gradient(180deg, #f4f9fe 0%, #e8f1f9 42%, #edf5fc 100%);
        color: var(--amn-text);
      }

      .topbar {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 24px;
        background: linear-gradient(90deg, var(--amn-navy), var(--amn-blue));
        color: #fff;
      }

      .brand-fallback {
        font-weight: 700;
        letter-spacing: 0.2px;
      }

      .content {
        max-width: 900px;
        margin: 48px auto;
        padding: 0 16px;
      }

      .panel {
        background: #fff;
        border: 1px solid var(--amn-border);
        border-radius: 12px;
        padding: 22px;
        box-shadow: 0 8px 20px rgba(0, 47, 108, 0.08);
      }

      .badge {
        display: inline-block;
        padding: 8px 12px;
        border-radius: 8px;
        background: #ffe6cc;
        border: 1px solid #f7b267;
        color: #5c2700;
        font-weight: 700;
      }

      a {
        color: var(--amn-blue);
        font-weight: 700;
      }
    </style>
  </head>
  <body>
    <header class="topbar">
      <span class="brand-fallback">AMN Healthcare</span>
      <strong>Voice Operations Portal</strong>
    </header>

    <main class="content">
      <section class="panel">
        <h1>Genesys Admin</h1>
        <p class="badge">Placeholder Page</p>
        <p>
          This page is reserved for the future Genesys Admin workflow.
          Development and deployments for Genesys Admin are intended to be handled independently from Cisco Admin.
        </p>
        <ul>
          <li>LAB first, then Production rollout.</li>
          <li>Separate code path and change process from Cisco Admin.</li>
          <li>Use the same Ubuntu server with independent service restart ownership.</li>
        </ul>
        <p><a href="/">Back to Cisco Landing Page</a></p>
      </section>
    </main>
  </body>
</html>
"""


@app.post("/login")
def login(
  cucm_host: str = Form(...),
  cucm_user: str = Form(...),
  cucm_pass: str = Form(...),
):
  ok, message = _validate_cucm_login(cucm_host.strip(), cucm_user.strip(), cucm_pass)
  if not ok:
    safe = escape(message)
    return HTMLResponse(
      f"""
<html><body style=\"font-family:Segoe UI,Arial,sans-serif;padding:24px;\">
  <h3>Login Failed</h3>
  <p>{safe}</p>
  <p><a href=\"/\">Back to Login</a></p>
</body></html>
""",
      status_code=401,
    )

  session_id = _create_auth_session(cucm_host, cucm_user)
  response = RedirectResponse(url="/menu", status_code=303)
  response.set_cookie(
    key=SESSION_COOKIE_NAME,
    value=session_id,
    httponly=True,
    samesite="lax",
    secure=True,
    max_age=SESSION_IDLE_TIMEOUT_SECONDS,
  )
  return response


@app.get("/logout")
def logout(request: Request):
  session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
  if session_id:
    AUTH_SESSIONS.pop(session_id, None)

  response = RedirectResponse(url="/", status_code=303)
  response.delete_cookie(SESSION_COOKIE_NAME)
  return response


@app.get("/menu", response_class=HTMLResponse)
def menu_page(request: Request):
  session = _get_auth_session(request) or {}
  session_username = str(session.get("username", ""))
  auth_user = escape(session_username)
  auth_cucm_host = str(session.get("cucm_host", ""))
  env_text, env_css_class = _get_environment_label(auth_cucm_host)
  admin_card_html = "" if not _is_admin_user(session_username) else """
        <a class=\"hero-link-card\" href=\"/menu-admin\">
          <strong>Administrative Items</strong>
          <span>Open bulk tools, strike workflows, exports, and translation lookups.</span>
        </a>
"""
  html = """
<html>
  <head>
    <title>Cisco Voice Server Automation Site - Restricted Access</title>
    <style>
      :root {
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-sky: #eaf4ff;
        --amn-text-soft: #4e6a84;
        --amn-text: #12304a;
        --amn-border: #c8dbee;
        --amn-panel-border: rgba(0, 47, 108, 0.12);
        --amn-shadow: 0 14px 30px rgba(0, 47, 108, 0.11);
      }

      body {
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        margin: 0;
        background: linear-gradient(180deg, #f7fbff 0%, #edf5fc 100%);
        color: var(--amn-text);
      }

      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 10px 16px;
        background:
          linear-gradient(120deg, rgba(0, 47, 108, 0.98), rgba(0, 94, 184, 0.94)),
          linear-gradient(90deg, var(--amn-navy), var(--amn-blue));
        color: #fff;
        box-shadow: 0 12px 28px rgba(0, 47, 108, 0.22);
        border-bottom: 1px solid rgba(255, 255, 255, 0.16);
      }

      .topbar-brand {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .topbar-brand strong {
        font-size: 16px;
        letter-spacing: 0.2px;
      }

      .topbar-actions {
        display: flex;
        align-items: center;
        gap: 10px;
      }

      .topbar-btn {
        display: inline-block;
        padding: 7px 12px;
        border-radius: 10px;
        font-size: 12px;
        font-weight: 700;
        text-decoration: none;
        border: 1px solid rgba(255, 255, 255, 0.65);
        transition: transform 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
      }

      .topbar-btn-login {
        color: #fff;
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(8px);
      }

      .topbar-btn-logout {
        color: #fff;
        background: linear-gradient(180deg, #cb3b2f, #9f2018);
        border-color: #f0a79c;
      }

      .topbar-btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 8px 18px rgba(0, 0, 0, 0.16);
      }

      .logo {
        height: 28px;
        width: auto;
        border-radius: 4px;
        background: #fff;
        padding: 3px;
      }

      .brand-fallback {
        font-weight: 700;
        letter-spacing: 0.6px;
        text-transform: uppercase;
        font-size: 12px;
        opacity: 0.86;
      }

      .content {
        max-width: 1400px;
        margin: 8px auto 14px auto;
        padding: 0 12px 12px 12px;
      }

      .page-hero {
        position: relative;
        overflow: hidden;
        padding: 12px 14px;
        margin-bottom: 10px;
        border-radius: 12px;
        background:
          linear-gradient(135deg, rgba(255, 255, 255, 0.96), rgba(239, 247, 255, 0.95)),
          linear-gradient(180deg, #ffffff, #eef6ff);
        border: 1px solid rgba(0, 47, 108, 0.1);
        box-shadow: var(--amn-shadow);
      }

      .page-hero::after {
        content: none;
        position: absolute;
        right: -80px;
        top: -60px;
        width: 280px;
        height: 280px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(0, 94, 184, 0.18), transparent 68%);
        pointer-events: none;
      }

      .page-kicker {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 5px 9px;
        border-radius: 999px;
        background: rgba(0, 94, 184, 0.08);
        color: var(--amn-blue);
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 0.4px;
        text-transform: uppercase;
      }

      .page-title-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 6px;
      }

      .page-title-block {
        max-width: 780px;
      }

      .page-title {
        margin: 0;
        color: var(--amn-navy);
        font-size: 22px;
        line-height: 1.1;
      }

      .page-subtitle {
        margin: 4px 0 0 0;
        color: var(--amn-text-soft);
        font-size: 12px;
        line-height: 1.35;
      }

      .page-meta-card {
        min-width: 180px;
        padding: 8px 10px;
        border-radius: 10px;
        background: linear-gradient(180deg, rgba(0, 47, 108, 0.96), rgba(0, 94, 184, 0.92));
        color: #fff;
        box-shadow: 0 14px 28px rgba(0, 47, 108, 0.22);
      }

      .page-meta-label {
        display: block;
        font-size: 10px;
        font-weight: 800;
        letter-spacing: 0.5px;
        opacity: 0.76;
        text-transform: uppercase;
      }

      .page-meta-value {
        display: block;
        margin-top: 2px;
        font-size: 14px;
        font-weight: 700;
      }

      .page-meta-note {
        margin: 4px 0 0 0;
        font-size: 11px;
        line-height: 1.3;
        color: rgba(255, 255, 255, 0.86);
      }

      .hero-link-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 8px;
        margin-top: 8px;
      }

      .hero-link-card {
        display: block;
        padding: 7px 10px;
        border-radius: 10px;
        background: rgba(255, 255, 255, 0.9);
        border: 1px solid rgba(0, 47, 108, 0.1);
        color: inherit;
        text-decoration: none;
        box-shadow: 0 10px 20px rgba(0, 47, 108, 0.06);
        transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
      }

      .hero-link-card:hover {
        transform: translateY(-2px);
        border-color: rgba(0, 94, 184, 0.3);
        box-shadow: 0 14px 28px rgba(0, 47, 108, 0.11);
      }

      .hero-link-card strong {
        display: block;
        color: var(--amn-navy);
        margin-bottom: 0;
        font-size: 12px;
      }

      .hero-link-card span {
        display: none;
        font-size: 12px;
        color: var(--amn-text-soft);
        line-height: 1.5;
      }

      .env-banner {
        display: inline-block;
        margin: 4px 0 0 0;
        padding: 6px 10px;
        border-radius: 10px;
        font-weight: 700;
        letter-spacing: 0.1px;
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.3);
      }

      .env-banner-prod {
        color: #083252;
        background: #d8ecff;
        border: 1px solid #8bb9e2;
      }

      .env-banner-lab {
        color: #5c2700;
        background: #ffe6cc;
        border: 1px solid #f7b267;
      }

      h2 {
        margin-top: 6px;
      }

      h3 {
        margin: 10px 0 6px 0;
        color: var(--amn-navy);
        font-size: 18px;
      }

      .portal-shell {
        display: grid;
        grid-template-columns: 280px minmax(0, 1fr);
        gap: 14px;
        align-items: start;
        margin-top: 8px;
      }

      .portal-sidebar {
        position: sticky;
        top: 58px;
        background: linear-gradient(180deg, rgba(0, 47, 108, 0.97), rgba(7, 75, 138, 0.96));
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 16px;
        padding: 12px;
        box-shadow: 0 18px 36px rgba(0, 47, 108, 0.18);
      }

      .portal-sidebar h4 {
        margin: 6px 8px 12px 8px;
        color: #fff;
        font-size: 14px;
        letter-spacing: 0.3px;
      }

      .portal-nav {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .portal-nav-btn {
        width: 100%;
        text-align: left;
        background: rgba(255, 255, 255, 0.09);
        color: rgba(255, 255, 255, 0.94);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 10px;
        padding: 9px 10px;
        font-size: 13px;
        font-weight: 600;
        transition: transform 0.18s ease, background 0.18s ease, border-color 0.18s ease;
      }

      .portal-nav-btn:hover {
        background: rgba(255, 255, 255, 0.16);
        border-color: rgba(255, 255, 255, 0.24);
        transform: translateX(2px);
      }

      .portal-nav-btn.active {
        background: linear-gradient(90deg, #ffffff, #ecf6ff);
        color: var(--amn-navy);
        border-color: rgba(255, 255, 255, 0.92);
        box-shadow: 0 12px 24px rgba(0, 0, 0, 0.12);
      }

      .portal-nav-btn-danger {
        background: rgba(203, 59, 47, 0.16);
        color: #ffd9d5;
        border-color: rgba(255, 167, 158, 0.26);
      }

      .portal-nav-btn-danger:hover {
        background: rgba(203, 59, 47, 0.24);
      }

      .portal-nav-btn-danger.active {
        background: linear-gradient(180deg, #d64e41, #a4221b);
        color: #fff;
        border-color: rgba(255, 255, 255, 0.2);
      }

      .portal-main {
        min-width: 0;
      }

      .tool-panel {
        display: none;
      }

      .tool-panel.active {
        display: block;
      }

      form,
      .build-user-output,
      .offboard-output,
      .secondary-output {
        background: rgba(255, 255, 255, 0.93);
        border: 1px solid var(--amn-panel-border);
        border-radius: 14px;
        padding: 10px;
        box-shadow: var(--amn-shadow);
        backdrop-filter: blur(6px);
      }

      form br + br {
        display: none;
      }

      input,
      select,
      button,
      textarea {
        border-radius: 10px;
        border: 1px solid var(--amn-border);
      }

      input,
      select {
        min-height: 32px;
        padding: 5px 9px;
        width: min(520px, 100%);
        background: rgba(255, 255, 255, 0.96);
      }

      input:focus,
      select:focus,
      textarea:focus {
        outline: none;
        border-color: rgba(0, 94, 184, 0.55);
        box-shadow: 0 0 0 4px rgba(0, 94, 184, 0.12);
      }

      button {
        background: linear-gradient(180deg, #0c77d8, #005eb8);
        color: #fff;
        border: none;
        padding: 7px 11px;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 8px 18px rgba(0, 94, 184, 0.16);
        transition: transform 0.18s ease, box-shadow 0.18s ease, filter 0.18s ease;
      }

      button:hover {
        filter: brightness(1.04);
        transform: translateY(-1px);
        box-shadow: 0 12px 22px rgba(0, 94, 184, 0.2);
      }

      a {
        color: var(--amn-blue);
        font-weight: 700;
      }

      hr {
        border: none;
        border-top: 1px solid var(--amn-border);
        margin: 22px 0;
      }

      .build-user-layout {
        display: flex;
        gap: 12px;
        align-items: flex-start;
        flex-wrap: wrap;
      }

      .jabber-check-layout {
        display: flex;
        gap: 12px;
        align-items: flex-start;
        flex-wrap: wrap;
      }

      .jabber-check-form {
        flex: 1 1 420px;
        min-width: 320px;
      }

      .portal-main form input[name="cucm_user"],
      .portal-main form input[name="cucm_pass"] {
        width: min(130px, 100%);
      }

      #person-lookup-form input[name="last_name"],
      #person-lookup-form input[name="first_name"] {
        width: min(260px, 100%);
      }

      .compact-inline-row {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }

      .compact-inline-row span {
        display: inline-block;
        width: 220px;
        font-weight: 600;
      }

      .jabber-check-output {
        flex: 1 1 480px;
        min-width: 320px;
        padding: 10px 12px;
        background: rgba(255, 255, 255, 0.88);
        border: 1px solid var(--amn-panel-border);
        border-radius: 14px;
        box-shadow: var(--amn-shadow);
      }

      .jabber-check-output h4 {
        margin: 0 0 10px 0;
      }

      .jabber-check-frame {
        width: 100%;
        min-height: 170px;
        border: 1px solid var(--amn-border);
        border-radius: 12px;
        background: var(--amn-sky);
      }

      .jabber-check-status {
        color: #2c5c8a;
        min-height: 18px;
      }

      .build-user-form {
        flex: 1 1 420px;
        min-width: 320px;
      }

      .build-user-output {
        flex: 1 1 480px;
        min-width: 320px;
        padding: 12px;
      }

      .build-user-output h4 {
        margin: 0 0 10px 0;
      }

      .build-user-output textarea {
        width: 100%;
        height: 300px;
        font-family: Consolas, monospace;
        background: linear-gradient(180deg, #f4faff, #eaf4ff);
        color: #0f2940;
      }

      .build-user-status {
        color: #2c5c8a;
        min-height: 18px;
      }

      .offboard-layout {
        display: flex;
        gap: 12px;
        align-items: flex-start;
        flex-wrap: wrap;
      }

      .offboard-form {
        flex: 1 1 420px;
        min-width: 320px;
      }

      .offboard-h3 {
        color: #b00020;
        font-weight: 900;
        letter-spacing: 0.2px;
        text-transform: uppercase;
      }

      .offboard-form .offboard-danger-btn {
        background: #b00020;
        border: 2px solid #7a0015;
        color: #ffffff;
        font-weight: 800;
        box-shadow: 0 0 0 2px rgba(176, 0, 32, 0.15);
      }

      .offboard-form .offboard-danger-btn:hover {
        background: #7a0015;
      }

      .offboard-output {
        flex: 1 1 480px;
        min-width: 320px;
        padding: 12px;
      }

      .offboard-output h4 {
        margin: 0 0 10px 0;
      }

      .offboard-output textarea {
        width: 100%;
        height: 300px;
        font-family: Consolas, monospace;
        background: linear-gradient(180deg, #f4faff, #eaf4ff);
        color: #0f2940;
      }

      .offboard-status {
        color: #2c5c8a;
        min-height: 18px;
      }

      .secondary-layout {
        display: flex;
        gap: 12px;
        align-items: flex-start;
        flex-wrap: wrap;
      }

      .secondary-form {
        flex: 1 1 420px;
        min-width: 320px;
      }

      .secondary-output {
        flex: 1 1 480px;
        min-width: 320px;
        padding: 12px;
      }

      .secondary-output h4 {
        margin: 0 0 10px 0;
      }

      .secondary-output textarea {
        width: 100%;
        height: 300px;
        font-family: Consolas, monospace;
        background: linear-gradient(180deg, #f4faff, #eaf4ff);
        color: #0f2940;
      }

      .secondary-status {
        color: #2c5c8a;
        min-height: 18px;
      }

      @media (max-width: 980px) {
        .topbar {
          padding: 8px 10px;
        }

        .compact-inline-row span {
          width: auto;
        }

        .portal-shell {
          grid-template-columns: 1fr;
        }

        .portal-sidebar {
          position: static;
        }

        .page-hero {
          padding: 10px 8px;
        }

        .page-title {
          font-size: 20px;
        }

        .portal-nav {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .build-user-output textarea {
          height: 230px;
        }

        .offboard-output textarea {
          height: 230px;
        }

        .secondary-output textarea {
          height: 230px;
        }
      }
    </style>
  </head>
  <body>
    <header class="topbar">
      <div class="topbar-brand">
        <span class="brand-fallback">AMN Healthcare</span>
        <strong>Voice Operations Portal</strong>
      </div>
      <div class="topbar-actions">
        <a class="topbar-btn topbar-btn-login" href="/">Log In</a>
        <a class="topbar-btn topbar-btn-logout" href="/logout">Log Out</a>
      </div>
    </header>

    <main class="content">
    <section class="page-hero">
      <span class="page-kicker">Internal Operations Portal</span>
      <div class="page-title-row">
        <div class="page-title-block">
          <h2 class="page-title">Cisco Voice Server Automation</h2>
          <p class="page-subtitle">CUCM and Unity operations with fast navigation and inline outputs.</p>
          <div class="env-banner __ENV_CLASS__">__ENV_TEXT__</div>
        </div>
        <aside class="page-meta-card">
          <span class="page-meta-label">Authenticated Operator</span>
          <span class="page-meta-value">__AUTH_USER__</span>
          <p class="page-meta-note">Session is locked to selected environment.</p>
        </aside>
      </div>
      <div class="hero-link-grid">
        <a class="hero-link-card" href="/">
          <strong>Landing Page</strong>
          <span>Return to login and environment selection.</span>
        </a>
__ADMIN_CARD__
        <a class="hero-link-card" href="/download/audit-trail">
          <strong>Audit Trail CSV</strong>
          <span>Download recorded portal activity for review and traceability.</span>
        </a>
        <a class="hero-link-card" href="/genesys-admin">
          <strong>Genesys Placeholder</strong>
          <span>Reserved path for the separate Genesys administration workflow.</span>
        </a>
      </div>
    </section>

    <div class="portal-shell">
      <aside class="portal-sidebar">
        <h4>Operations Menu</h4>
        <div class="portal-nav">
          <button type="button" class="portal-nav-btn active" data-panel="personlookup">Employee Lookup by Name</button>
          <button type="button" class="portal-nav-btn" data-panel="extensionlookup">Extension Reverse Lookup</button>
          <button type="button" class="portal-nav-btn" data-panel="precheck">Check for Existing Jabber Configuration</button>
          <button type="button" class="portal-nav-btn" data-panel="build">Build User - Build Cisco Jabber Laptop</button>
          <button type="button" class="portal-nav-btn" data-panel="namechange">Employee Name Change-Update Jabber/VM</button>
          <button type="button" class="portal-nav-btn" data-panel="pin">Reset Voicemail PIN</button>
          <button type="button" class="portal-nav-btn" data-panel="ad">Update AD Telephone/ipPhone Field Only</button>
          <button type="button" class="portal-nav-btn" data-panel="tct">Add in Jabber iPhone</button>
          <button type="button" class="portal-nav-btn" data-panel="bot">Add in Jabber Android</button>
          <button type="button" class="portal-nav-btn" data-panel="jabbernotify">Send Jabber Number/Training Notification</button>
          <button type="button" class="portal-nav-btn" data-panel="mobilejabbernotify">Re-send Jabber Mobile Email Instructions</button>
          <button type="button" class="portal-nav-btn" data-panel="rebuild">Re-Build Jabber CSF (from Offboard Audit)</button>
        </div>
      </aside>

      <section class="portal-main">

    <section class="tool-panel active" data-panel="personlookup">

    <h3>Person Lookup - Search by Name</h3>
    <p>Search for a user by last name (and optional first name) to view their extension, email, and associated Jabber devices.</p>

    <div class="jabber-check-layout" style="display:block;">
      <form id="person-lookup-form" class="jabber-check-form" style="margin-bottom:14px;">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        Last Name:<br>
        <input name="last_name" placeholder="Smith" required><br><br>

        First Name (optional):<br>
        <input name="first_name" placeholder="John"><br><br>

        <div class="action-row">
          <button id="person-lookup-btn" type="submit">Search</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="jabber-check-output" aria-live="polite" style="margin-top:0;">
        <h4>Search Results</h4>
        <p id="person-lookup-status" class="jabber-check-status">Enter a last name and click Search.</p>
        <div id="person-lookup-results" style="overflow-x: auto;"></div>
      </section>
    </div>

    <script>
      (function () {
        const form = document.getElementById("person-lookup-form");
        const statusEl = document.getElementById("person-lookup-status");
        const resultsEl = document.getElementById("person-lookup-results");

        if (!form || !statusEl || !resultsEl) return;

        form.addEventListener("submit", async function (event) {
          event.preventDefault();
          statusEl.textContent = "Searching...";
          resultsEl.innerHTML = "";

          try {
            const formData = new FormData(form);
            const response = await fetch("/lookup/person", {
              method: "POST",
              body: formData,
              credentials: "same-origin",
            });

            const payload = await response.json();

            if (!response.ok || !payload.ok) {
              const msg = (payload.error && payload.error.message) || "Search failed.";
              throw new Error(msg);
            }

            const results = payload.results || [];
            if (!results.length) {
              statusEl.textContent = "No users found matching that name.";
              return;
            }

            statusEl.textContent = `Found ${results.length} user(s).`;

            let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
            html += '<thead><tr style="background:#005eb8; color:#fff;">';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Extension</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Email</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Devices</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Actions</th>';
            html += '</tr></thead><tbody>';

            results.forEach(function (r, i) {
              const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
              const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
              const ext = r.primary_extension || "\u2014";
              const email = r.email || "\u2014";
              const telephone = r.telephone || "\u2014";
              const uid = r.userid || "";
              const devList = (r.devices || []).map(function (d) {
                const exts = (d.extensions || []).join(", ") || "\u2014";
                return "<strong>" + d.name + "</strong> <span style='color:#555;font-size:12px;'>[" + d.type + "] " + exts + "</span>";
              }).join("<br>") || "\u2014";

              const btnStyle = "display:inline-block;margin:2px 3px 2px 0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;";
              const actionBtns =
                `<button type="button" style="${btnStyle}background:#005eb8;color:#fff;" onclick="prefillPanel('precheck','${uid}')">Check Jabber</button>` +
                `<button type="button" style="${btnStyle}background:#237741;color:#fff;" onclick="prefillPanel('build','${uid}')">Build Jabber</button>` +
                `<button type="button" style="${btnStyle}background:#0e7490;color:#fff;" onclick="prefillPanel('tct','${uid}')">Build iPhone</button>` +
                `<button type="button" style="${btnStyle}background:#7c3aed;color:#fff;" onclick="prefillPanel('bot','${uid}')">Build Android</button>` +
                `<button type="button" style="${btnStyle}background:#0f766e;color:#fff;" onclick="prefillPanel('mobilejabbernotify','${uid}','${telephone}')">Re-send Mobile Email</button>` +
                `<button type="button" style="${btnStyle}background:#1f7a3d;color:#fff;" data-lookup-notify-uid="${uid}" data-lookup-notify-tel="${(r.telephone || "")}">Send Notification</button>` +
                `<button type="button" style="${btnStyle}background:#8a5a00;color:#fff;" onclick="prefillPanel('namechange','${uid}')">Name Update</button>`;

              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
              html += '<td style="padding:7px 10px;">' + name + '</td>';
              html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
              html += '<td style="padding:7px 10px; font-weight:700; color:#002f6c;">' + ext + '</td>';
              html += '<td style="padding:7px 10px;">' + email + '</td>';
              html += '<td style="padding:7px 10px;">' + telephone + '</td>';
              html += '<td style="padding:7px 10px; line-height:1.6;">' + devList + '</td>';
              html += '<td style="padding:7px 10px; white-space:nowrap;">' + actionBtns + '</td>';
              html += '</tr>';
            });

            html += '</tbody></table>';
            resultsEl.innerHTML = html;

            resultsEl.querySelectorAll('button[data-lookup-notify-uid]').forEach(function (btn) {
              btn.addEventListener("click", async function () {
                const uid = btn.getAttribute("data-lookup-notify-uid") || "";
                const tel = btn.getAttribute("data-lookup-notify-tel") || "";
                const userField = form.querySelector('input[name="cucm_user"]');
                const passField = form.querySelector('input[name="cucm_pass"]');
                const cucmUser = ((userField && userField.value) || "").trim();
                const cucmPass = (passField && passField.value) || "";

                if (!cucmUser || !cucmPass) {
                  statusEl.textContent = "Enter CUCM username/password before sending notification.";
                  return;
                }

                btn.disabled = true;
                statusEl.textContent = `Sending Jabber notification for ${uid}...`;
                try {
                  const sf = new FormData();
                  sf.append("cucm_user", cucmUser);
                  sf.append("cucm_pass", cucmPass);
                  sf.append("target_user", uid);
                  sf.append("telephone", tel);

                  const sr = await fetch("/send/jabber-ready-email", {
                    method: "POST",
                    body: sf,
                    credentials: "same-origin",
                    headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                  });
                  const sp = await sr.json();
                  if (!sr.ok || !sp.ok) {
                    throw new Error((sp && sp.detail) || "Send failed.");
                  }
                  statusEl.textContent = "Notification sent: " + (sp.detail || "Email sent successfully.");
                } catch (err) {
                  statusEl.textContent = "Send failed: " + ((err && err.message) || "Unknown error.");
                  btn.disabled = false;
                }
              });
            });

          } catch (err) {
            statusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
          }
        });
      })();
    </script>

    </section>

    <section class="tool-panel" data-panel="extensionlookup">

    <h3>Extension Reverse Lookup</h3>
    <p>Enter a DN pattern (exact or partial) to find which device and user it is assigned to.</p>

    <div class="jabber-check-layout">
      <form id="extension-lookup-form" class="jabber-check-form">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        Extension / DN Pattern:<br>
        <input name="pattern" placeholder="4695551234" required><br><br>

        <div class="action-row">
          <button id="extension-lookup-btn" type="submit">Look Up Extension</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="jabber-check-output" aria-live="polite" style="flex: 1 1 600px; min-width: 320px;">
        <h4>Lookup Result</h4>
        <p id="extension-lookup-status" class="jabber-check-status">Enter a DN and click Look Up Extension.</p>
        <div id="extension-lookup-results" style="overflow-x: auto;"></div>
      </section>
    </div>

    <script>
      (function () {
        const form = document.getElementById("extension-lookup-form");
        const statusEl = document.getElementById("extension-lookup-status");
        const resultsEl = document.getElementById("extension-lookup-results");

        if (!form || !statusEl || !resultsEl) return;

        form.addEventListener("submit", async function (event) {
          event.preventDefault();
          statusEl.textContent = "Looking up...";
          resultsEl.innerHTML = "";

          try {
            const formData = new FormData(form);
            const response = await fetch("/lookup/extension", {
              method: "POST",
              body: formData,
              credentials: "same-origin",
            });

            const payload = await response.json();

            if (!response.ok || !payload.ok) {
              const msg = (payload.error && payload.error.message) || "Lookup failed.";
              throw new Error(msg);
            }

            const matches = payload.matches || [];
            if (!matches.length) {
              statusEl.textContent = `No results found for "${payload.pattern || ""}"`;
              return;
            }

            statusEl.textContent = `Found ${matches.length} result(s) for "${payload.pattern || ""}".`;

            let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
            html += '<thead><tr style="background:#005eb8; color:#fff;">';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Extension</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Partition</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Device</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Type</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Owner</th>';
            html += '<th style="padding:8px 10px; text-align:left;">All Lines on Device</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Actions</th>';
            html += '</tr></thead><tbody>';

            matches.forEach(function (m, i) {
              const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
              const dev = m.device_name || "<em style='color:#888;'>Unassigned</em>";
              const devType = m.device_type || "\u2014";
              const uid = (m.user && m.user.userid) || m.owner_userid || "";
              const ownerName = (m.user && (m.user.display_name || ((m.user.first_name || "") + " " + (m.user.last_name || "")).trim())) || "";
              const ownerCell = uid ? (ownerName ? ownerName + "<br><span style='font-family:Consolas,monospace;font-size:11px;'>" + uid + "</span>" : uid) : "\u2014";
              const allLines = (m.all_lines || []).map(function (l) { return l.pattern; }).join(", ") || "\u2014";

              const btnStyle = "display:inline-block;margin:2px 3px 2px 0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;";
              const actionBtns = uid
                ? `<button type="button" style="${btnStyle}background:#005eb8;color:#fff;" onclick="prefillPanel('precheck','${uid}')">Check Jabber</button>` +
                  `<button type="button" style="${btnStyle}background:#237741;color:#fff;" onclick="prefillPanel('build','${uid}')">Build</button>` +
                  `<button type="button" style="${btnStyle}background:#0f766e;color:#fff;" onclick="prefillPanel('mobilejabbernotify','${uid}','${m.pattern || ""}')">Re-send Mobile Email</button>`
                : "\u2014";

              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
              html += '<td style="padding:7px 10px; font-weight:700; color:#002f6c; font-family:Consolas,monospace;">' + m.pattern + '</td>';
              html += '<td style="padding:7px 10px; font-size:12px;">' + (m.partition || "\u2014") + '</td>';
              html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + dev + '</td>';
              html += '<td style="padding:7px 10px; font-size:12px;">' + devType + '</td>';
              html += '<td style="padding:7px 10px;">' + ownerCell + '</td>';
              html += '<td style="padding:7px 10px; font-size:12px; color:#355978;">' + allLines + '</td>';
              html += '<td style="padding:7px 10px; white-space:nowrap;">' + actionBtns + '</td>';
              html += '</tr>';
            });

            html += '</tbody></table>';
            resultsEl.innerHTML = html;

          } catch (err) {
            statusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
          }
        });
      })();
    </script>
    </section>

    <section class="tool-panel" data-panel="precheck">

    <h3>Pre-Check: Is Jabber Already Built?</h3>
    <p>Use this quick lookup before building or offboarding. It returns device name, Jabber extension, and voicemail extension.</p>

    <div class="jabber-check-layout">
      <form id="jabber-check-form" class="target-user-form jabber-check-form" action="/check/jabber-status?embedded=1" method="post" target="jabber-check-frame">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID to check:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button id="jabber-check-btn" type="submit">Check Jabber Build Status</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="jabber-check-output" aria-live="polite">
        <h4>Jabber Lookup Result</h4>
        <p id="jabber-check-status" class="jabber-check-status">Run lookup to load results below.</p>
        <iframe id="jabber-check-frame" name="jabber-check-frame" class="jabber-check-frame" title="Jabber Lookup Result"></iframe>
      </section>
    </div>
    </section>

    <section class="tool-panel" data-panel="build">

    <h3>Build Cisco Jabber Laptop and Voicemail - New Hire or New Jabber Laptop/VM Add</h3>
    <p>Authentication note: Cisco Callmanager credentials entered below are reused for Unity voicemail and Active Directory actions.</p>

    <div class="build-user-layout">
      <form id="build-user-form" class="target-user-form build-user-form" action="javascript:void(0)" method="post" onsubmit="return false;">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to Build Jabber for:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        DN Type:<br>
        <select name="dn_type">
          <option value="recruiter">Recruiter (469)</option>
          <option value="general" selected>General FTE (214)</option>
          <option value="strike">Strike (945)</option>
        </select><br><br>

        <div class="action-row">
          <button id="build-user-btn" type="button">Run Build User CSF Phone</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="build-user-output" aria-live="polite">
        <h4>Build User Output Preview</h4>
        <p id="build-user-status" class="build-user-status">Run Build User to view output here.</p>
        <p>
          <a id="build-user-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="build-user-preview" readonly></textarea>
      </section>
    </div>

    <script>
      (function () {
        const form = document.getElementById("build-user-form");
        const button = document.getElementById("build-user-btn");
        const statusEl = document.getElementById("build-user-status");
        const outputEl = document.getElementById("build-user-preview");
        const downloadEl = document.getElementById("build-user-download");

        if (!form || !button || !statusEl || !outputEl || !downloadEl) {
          return;
        }

        async function runBuild() {
          const targetUserField = form.querySelector('input[name="target_user"]');
          const targetUser = ((targetUserField && targetUserField.value) || "").trim();
          if (!targetUser) {
            statusEl.textContent = "Enter a User ID to build.";
            if (targetUserField) {
              targetUserField.focus();
            }
            return;
          }

          statusEl.textContent = "Running Build User...";
          outputEl.value = "";
          downloadEl.style.display = "none";
          downloadEl.removeAttribute("href");

          try {
            const formData = new FormData(form);
            const response = await fetch("/build/user-csf-phone?inline=1", {
              method: "POST",
              body: formData,
              credentials: "same-origin",
            });

            const responseText = await response.text();
            let payload = null;
            try {
              payload = JSON.parse(responseText || "{}");
            } catch (_parseErr) {
              throw new Error(responseText || `Request failed with status ${response.status}`);
            }

            if (!response.ok) {
              throw new Error((payload && payload.detail) || `Request failed with status ${response.status}`);
            }

            outputEl.value = payload.output_text || "";
            statusEl.textContent = `Completed: ${payload.filename || "build_user_output.csv"}`;
            if (payload.download_url) {
              downloadEl.href = payload.download_url;
              downloadEl.style.display = "inline";
            }

            if (targetUserField) {
              targetUserField.value = "";
            }
          } catch (err) {
            statusEl.textContent = "Build User failed. Review output and retry.";
            outputEl.value = (err && err.message) ? err.message : "Unknown error.";
          }
        }

        form.addEventListener("submit", function (event) {
          event.preventDefault();
          checkForDuplicateDevices(form, ["csf"]).then((proceed) => { if (proceed) runBuild(); });
        });

        button.addEventListener("click", function (event) {
          event.preventDefault();
          checkForDuplicateDevices(form, ["csf"]).then((proceed) => { if (proceed) runBuild(); });
        });

      })();
    </script>
    </section>

    <section class="tool-panel" data-panel="teams-telephony">

    <h3>Create Teams Telephony User</h3>
    <p>Builds Teams telephony from template: lookup email, choose available DN, delete line, create translation pattern, update AD fields, and print PowerShell handoff commands.</p>

    <div class="build-user-layout">
      <form id="teams-telephony-form" class="target-user-form build-user-form" action="javascript:void(0)" method="post" onsubmit="return false;">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        <div style="margin: 0 0 14px 0; padding: 12px; border: 1px solid #c8dbee; border-radius: 10px; background: #f7fbff;">
          <strong style="display:block; margin-bottom:10px; color:#002f6c;">Lookup by Name</strong>
          Last Name:<br>
          <input id="teams-lookup-last-name" placeholder="Smith" style="width:min(320px,100%);" required><br><br>

          First Name (optional):<br>
          <input id="teams-lookup-first-name" placeholder="John" style="width:min(320px,100%);"><br><br>

          <button id="teams-lookup-btn" type="button">Search User</button>
          <p id="teams-lookup-status" style="margin:10px 0 6px 0; color:#2c5c8a; min-height:18px;">Enter last name and click Search User.</p>
          <div id="teams-lookup-results" style="overflow-x:auto;"></div>
        </div>

        User ID for Teams Telephony user:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button id="teams-telephony-btn" type="button">Run Create Teams Telephony User</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="build-user-output" aria-live="polite">
        <h4>Teams Telephony Output Preview</h4>
        <p id="teams-telephony-status" class="build-user-status">Run Teams Telephony User to view output here.</p>
        <p>
          <a id="teams-telephony-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="teams-telephony-preview" readonly></textarea>
      </section>
    </div>

    <script>
      (function () {
        const form = document.getElementById("teams-telephony-form");
        const button = document.getElementById("teams-telephony-btn");
        const statusEl = document.getElementById("teams-telephony-status");
        const outputEl = document.getElementById("teams-telephony-preview");
        const downloadEl = document.getElementById("teams-telephony-download");
        const lookupBtn = document.getElementById("teams-lookup-btn");
        const lookupStatusEl = document.getElementById("teams-lookup-status");
        const lookupResultsEl = document.getElementById("teams-lookup-results");
        const lookupLastNameEl = document.getElementById("teams-lookup-last-name");
        const lookupFirstNameEl = document.getElementById("teams-lookup-first-name");

        if (!form || !button || !statusEl || !outputEl || !downloadEl) {
          return;
        }

        async function runCreateTeamsTelephonyUser() {
          const targetUserField = form.querySelector('input[name="target_user"]');
          const targetUser = ((targetUserField && targetUserField.value) || "").trim();
          if (!targetUser) {
            statusEl.textContent = "Enter a User ID to create.";
            if (targetUserField) {
              targetUserField.focus();
            }
            return;
          }

          statusEl.textContent = "Running Create Teams Telephony User...";
          outputEl.value = "";
          downloadEl.style.display = "none";
          downloadEl.removeAttribute("href");

          try {
            const formData = new FormData(form);
            const response = await fetch("/build/teams-telephony-user?inline=1", {
              method: "POST",
              body: formData,
              credentials: "same-origin",
            });

            const responseText = await response.text();
            let payload = null;
            try {
              payload = JSON.parse(responseText || "{}");
            } catch (_parseErr) {
              throw new Error(responseText || `Request failed with status ${response.status}`);
            }

            if (!response.ok) {
              throw new Error((payload && payload.detail) || `Request failed with status ${response.status}`);
            }

            outputEl.value = payload.output_text || "";
            statusEl.textContent = `Completed: ${payload.filename || "teams_telephony_user_output.csv"}`;
            if (payload.download_url) {
              downloadEl.href = payload.download_url;
              downloadEl.style.display = "inline";
            }

            if (targetUserField) {
              targetUserField.value = "";
            }
          } catch (err) {
            statusEl.textContent = "Create Teams Telephony User failed. Review output and retry.";
            outputEl.value = (err && err.message) ? err.message : "Unknown error.";
          }
        }

        form.addEventListener("submit", function (event) {
          event.preventDefault();
          runCreateTeamsTelephonyUser();
        });

        button.addEventListener("click", function (event) {
          event.preventDefault();
          runCreateTeamsTelephonyUser();
        });

        if (lookupBtn && lookupStatusEl && lookupResultsEl && lookupLastNameEl && lookupFirstNameEl) {
          lookupBtn.addEventListener("click", async function (event) {
            event.preventDefault();

            const userField = form.querySelector('input[name="cucm_user"]');
            const passField = form.querySelector('input[name="cucm_pass"]');
            const lastName = (lookupLastNameEl.value || "").trim();
            const firstName = (lookupFirstNameEl.value || "").trim();
            const cucmUser = ((userField && userField.value) || "").trim();
            const cucmPass = (passField && passField.value) || "";

            if (!lastName) {
              lookupStatusEl.textContent = "Last Name is required for lookup.";
              lookupLastNameEl.focus();
              return;
            }

            if (!cucmUser || !cucmPass) {
              lookupStatusEl.textContent = "Enter CUCM username/password above before searching.";
              return;
            }

            lookupStatusEl.textContent = "Searching...";
            lookupResultsEl.innerHTML = "";

            try {
              const lookupForm = new FormData();
              lookupForm.append("cucm_user", cucmUser);
              lookupForm.append("cucm_pass", cucmPass);
              lookupForm.append("last_name", lastName);
              lookupForm.append("first_name", firstName);

              const response = await fetch("/lookup/person", {
                method: "POST",
                body: lookupForm,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                const msg = (payload.error && payload.error.message) || "Search failed.";
                throw new Error(msg);
              }

              const results = payload.results || [];
              if (!results.length) {
                lookupStatusEl.textContent = "No users found matching that name.";
                return;
              }

              lookupStatusEl.textContent = `Found ${results.length} user(s).`;

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Email</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Action</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                const uid = r.userid || "";
                const email = r.email || "\u2014";
                const telephone = r.telephone || "\u2014";

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px;">' + email + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px;">';
                html += '<button type="button" data-teams-user="' + uid + '" style="background:#237741; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-weight:700; cursor:pointer;">Create Teams Telephony</button>';
                html += '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              lookupResultsEl.innerHTML = html;

              lookupResultsEl.querySelectorAll('button[data-teams-user]').forEach(function (btnEl) {
                btnEl.addEventListener('click', function () {
                  const uid = (btnEl.getAttribute('data-teams-user') || '').trim();
                  const targetUserField = form.querySelector('input[name="target_user"]');
                  if (targetUserField) {
                    targetUserField.value = uid;
                  }
                  runCreateTeamsTelephonyUser();
                });
              });
            } catch (err) {
              lookupStatusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        }

      })();
    </script>
    </section>

    <section class="tool-panel" data-panel="teams-telephony-remove">

    <h3>Remove Teams Telephony User</h3>
    <p>Safe removal flow: lookup user name + extension, find strict Teams translation pattern format, then delete translation pattern, rebuild inactive DN, and clear AD phone fields.</p>

    <div class="build-user-layout">
      <form id="teams-remove-form" class="target-user-form build-user-form" action="javascript:void(0)" method="post" onsubmit="return false;">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        <div style="margin: 0 0 14px 0; padding: 12px; border: 1px solid #c8dbee; border-radius: 10px; background: #fff6f6;">
          <strong style="display:block; margin-bottom:10px; color:#7a1020;">Lookup by Name</strong>
          Last Name:<br>
          <input id="teams-remove-last-name" placeholder="Smith" style="width:min(320px,100%);" required><br><br>

          First Name (optional):<br>
          <input id="teams-remove-first-name" placeholder="John" style="width:min(320px,100%);"><br><br>

          <button id="teams-remove-search-btn" type="button" onclick="if (window.runTeamsRemoveSearch) { window.runTeamsRemoveSearch(); } else { var s=document.getElementById('teams-remove-search-status'); if (s) { s.textContent='Search handler missing (JS did not load).'; } } return false;">Search User</button>
          <p id="teams-remove-search-status" style="margin:10px 0 6px 0; color:#7a1020; min-height:18px;">Enter last name and click Search User.</p>
          <div id="teams-remove-search-results" style="overflow-x:auto;"></div>
        </div>

        User ID for Teams Telephony removal:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button id="teams-remove-lookup-btn" type="button" onclick="if (window.runTeamsRemoveLookup) { window.runTeamsRemoveLookup(); } else { var st=document.getElementById('teams-remove-status'); var out=document.getElementById('teams-remove-preview'); if (st) { st.textContent='Lookup handler missing (JS did not load).'; } if (out) { out.value='Lookup handler missing (JS did not load).'; } } return false;">Lookup Teams Mapping</button>
          <button id="teams-remove-delete-btn" type="button" style="background:#b00020;" disabled onclick="if (window.runTeamsRemoveDelete) { window.runTeamsRemoveDelete(); } return false;">Delete + Rebuild Inactive DN</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="build-user-output" aria-live="polite">
        <h4>Teams Removal Output Preview</h4>
        <p id="teams-remove-status" class="build-user-status">Run Lookup Teams Mapping to validate strict pattern match before delete.</p>
        <p>
          <a id="teams-remove-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="teams-remove-preview" readonly></textarea>
      </section>
    </div>

    <script>
      // Keep this block deliberately simple to avoid blocking global menu script parsing.
      window.teamsRemoveLookupState = null;

      window.runTeamsRemoveSearch = async function () {
        const form = document.getElementById("teams-remove-form");
        const statusEl = document.getElementById("teams-remove-search-status");
        const resultsEl = document.getElementById("teams-remove-search-results");
        if (!form || !statusEl || !resultsEl) {
          return;
        }

        const userField = form.querySelector('input[name="cucm_user"]');
        const passField = form.querySelector('input[name="cucm_pass"]');
        const lastNameEl = document.getElementById("teams-remove-last-name");
        const firstNameEl = document.getElementById("teams-remove-first-name");
        const targetUserField = form.querySelector('input[name="target_user"]');

        const lastName = ((lastNameEl && lastNameEl.value) || "").trim();
        const firstName = ((firstNameEl && firstNameEl.value) || "").trim();
        const cucmUser = ((userField && userField.value) || "").trim();
        const cucmPass = (passField && passField.value) || "";

        if (!lastName) {
          statusEl.textContent = "Last Name is required for lookup.";
          if (lastNameEl) {
            lastNameEl.focus();
          }
          return;
        }

        if (!cucmUser || !cucmPass) {
          statusEl.textContent = "Enter CUCM username/password above before searching.";
          return;
        }

        statusEl.textContent = "Searching...";
        resultsEl.innerHTML = "";

        try {
          const lookupForm = new FormData();
          lookupForm.append("cucm_user", cucmUser);
          lookupForm.append("cucm_pass", cucmPass);
          lookupForm.append("last_name", lastName);
          lookupForm.append("first_name", firstName);

          const response = await fetch("/lookup/person", {
            method: "POST",
            body: lookupForm,
            credentials: "same-origin",
            headers: {
              "Accept": "application/json",
              "X-Requested-With": "XMLHttpRequest",
            },
          });

          const responseText = await response.text();
          let payload = null;
          try {
            payload = JSON.parse(responseText || "{}");
          } catch (_parseErr) {
            throw new Error(responseText || ("Request failed with status " + response.status));
          }

          if (!response.ok || !payload.ok) {
            const msg = (payload.error && payload.error.message) || payload.detail || "Search failed.";
            throw new Error(msg);
          }

          const results = payload.results || [];
          if (!results.length) {
            statusEl.textContent = "No users found matching that name.";
            return;
          }

          statusEl.textContent = "Found " + results.length + " user(s).";

          let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
          html += '<thead><tr style="background:#b00020; color:#fff;">';
          html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
          html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
          html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Email</th>';
          html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
          html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Action</th>';
          html += '</tr></thead><tbody>';

          results.forEach(function (r, i) {
            const bg = i % 2 === 0 ? "#fff7f8" : "#ffffff";
            const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
            const uid = r.userid || "";
            const email = r.email || "-";
            const telephone = r.telephone || "-";

            html += '<tr style="background:' + bg + '; border-bottom:1px solid #f0c8cf;">';
            html += '<td style="padding:7px 10px;">' + name + '</td>';
            html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
            html += '<td style="padding:7px 10px;">' + email + '</td>';
            html += '<td style="padding:7px 10px;">' + telephone + '</td>';
            html += '<td style="padding:7px 10px;">';
            html += '<button type="button" data-remove-user="' + uid + '" style="background:#b00020; color:#fff; border:none; border-radius:6px; padding:6px 10px; font-weight:700; cursor:pointer;">Use for Remove Teams</button>';
            html += '</td>';
            html += '</tr>';
          });

          html += '</tbody></table>';
          resultsEl.innerHTML = html;

          resultsEl.querySelectorAll('button[data-remove-user]').forEach(function (btnEl) {
            btnEl.addEventListener('click', function () {
              const uid = (btnEl.getAttribute('data-remove-user') || '').trim();
              if (targetUserField) {
                targetUserField.value = uid;
              }
            });
          });
        } catch (err) {
          statusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
          if (window.console && typeof window.console.error === "function") {
            console.error("Remove Teams search failed", err);
          }
        }
      };

      window.runTeamsRemoveLookup = async function () {
        const form = document.getElementById("teams-remove-form");
        const statusEl = document.getElementById("teams-remove-status");
        const outputEl = document.getElementById("teams-remove-preview");
        const deleteBtn = document.getElementById("teams-remove-delete-btn");
        const targetUserField = form ? form.querySelector('input[name="target_user"]') : null;
        if (!form || !statusEl || !outputEl || !deleteBtn) {
          return;
        }

        const cleanTargetUser = ((targetUserField && targetUserField.value) || "").trim();
        if (!cleanTargetUser) {
          statusEl.textContent = "Enter User ID for Teams Telephony removal or select one from Search results.";
          outputEl.value = "";
          if (targetUserField) {
            targetUserField.focus();
          }
          return;
        }

        statusEl.textContent = "Running lookup...";
        outputEl.value = "";
        deleteBtn.disabled = true;
        window.teamsRemoveLookupState = null;

        try {
          const response = await fetch("/teams-telephony/remove/lookup", {
            method: "POST",
            body: new FormData(form),
            credentials: "same-origin",
            headers: {
              "Accept": "application/json",
              "X-Requested-With": "XMLHttpRequest",
            },
          });

          const responseText = await response.text();
          let payload = null;
          try {
            payload = JSON.parse(responseText || "{}");
          } catch (_parseErr) {
            throw new Error(responseText || ("Request failed with status " + response.status));
          }

          if (!response.ok || !payload.ok) {
            const msg = (payload.error && payload.error.message) || payload.detail || "Lookup failed.";
            throw new Error(msg);
          }

          window.teamsRemoveLookupState = payload;
          statusEl.textContent = payload.match_found ? "Lookup completed. MATCHED" : "Lookup completed. NOT MATCHED";
          outputEl.value = [
            "User: " + (payload.target_user || ""),
            "Name: " + (((payload.first_name || "") + " " + (payload.last_name || "")).trim()),
            "Extension: " + (payload.extension || ""),
            "Expected Description: " + (payload.expected_description || ""),
            "Matched Pattern: " + (payload.pattern || "(none)"),
            "Matched Partition: " + (payload.route_partition || "(none)"),
            "Matched Description: " + (payload.description || "(none)"),
          ].join("\\n");

          if (payload.match_found) {
            deleteBtn.disabled = false;
          }
        } catch (err) {
          statusEl.textContent = "Lookup failed.";
          outputEl.value = ((err && err.message) || "Unknown error.");
          if (window.console && typeof window.console.error === "function") {
            console.error("Remove Teams lookup failed", err);
          }
        }
      };

      window.runTeamsRemoveDelete = async function () {
        const form = document.getElementById("teams-remove-form");
        const statusEl = document.getElementById("teams-remove-status");
        const outputEl = document.getElementById("teams-remove-preview");
        const deleteBtn = document.getElementById("teams-remove-delete-btn");
        const state = window.teamsRemoveLookupState;
        if (!form || !statusEl || !outputEl || !deleteBtn || !state || !state.match_found) {
          alert("Run lookup first and confirm strict match.");
          return;
        }

        if (!confirm("Delete Teams translation pattern and rebuild inactive DN for " + (state.target_user || "") + "?")) {
          return;
        }

        statusEl.textContent = "Running remove Teams Telephony workflow...";
        outputEl.value = "";
        deleteBtn.disabled = true;

        try {
          const response = await fetch("/teams-telephony/remove?inline=1", {
            method: "POST",
            body: new FormData(form),
            credentials: "same-origin",
          });

          const responseText = await response.text();
          let payload = {};
          try {
            payload = JSON.parse(responseText || "{}");
          } catch (_parseErr) {
            throw new Error(responseText || ("Request failed with status " + response.status));
          }
          if (!response.ok) {
            throw new Error((payload && payload.detail) || ("Request failed with status " + response.status));
          }

          outputEl.value = payload.output_text || "";
          statusEl.textContent = "Completed: " + (payload.filename || "remove_teams_telephony_output.csv");
        } catch (err) {
          statusEl.textContent = "Remove Teams Telephony failed.";
          outputEl.value = ((err || {}).message) || "Unknown error.";
        } finally {
          if (window.teamsRemoveLookupState && window.teamsRemoveLookupState.match_found) {
            deleteBtn.disabled = false;
          }
        }
      };
    </script>
    </section>

    <section class="tool-panel" data-panel="namechange">

    <h3>Employee Name Change-Update Jabber/VM (Update CUCM Phone/Line + Unity Display/SMTP)</h3>
    <p>
      This option reads Display Name from CUCM End User, updates all Jabber phone descriptions,
      updates line alerting/caller ID fields, and updates Unity voicemail Display Name and SMTP.
    </p>

    <div class="secondary-layout">
      <form id="called-name-form" class="target-user-form secondary-form" action="/called-name-change" method="post">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for name change update:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button type="submit">Run Employee Name Change-Update Jabber/VM</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="secondary-output" aria-live="polite">
        <h4>Employee Name Change-Update Jabber/VM Output Preview</h4>
        <p id="called-name-status" class="secondary-status">Run Employee Name Change-Update Jabber/VM to view output here.</p>
        <p>
          <a id="called-name-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="called-name-preview" readonly></textarea>
      </section>
    </div>
    </section>

    <section class="tool-panel" data-panel="pin">

    <h3>Reset Unity Voicemail PIN (Option 2)</h3>

    <div class="secondary-layout">
      <form id="reset-pin-form" class="secondary-form" action="/reset/unity-voicemail-pin" method="post">
        Unity Admin Username:<br>
        <input name="unity_user" value="__AUTH_USER__" required><br><br>

        Unity Admin Password:<br>
        <input type="password" name="unity_pass" required><br><br>

        Voicemail Username to Reset PIN for:<br>
        <input name="voicemail_user" placeholder="john.doe" required><br><br>

        New Voicemail PIN:<br>
        <input type="password" name="new_voicemail_pin" required><br><br>

        Confirm New Voicemail PIN:<br>
        <input type="password" name="confirm_voicemail_pin" required><br><br>

        <div class="action-row">
          <button type="submit">Run Reset Unity Voicemail PIN (Option 2)</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="secondary-output" aria-live="polite">
        <h4>Option 2 Output Preview</h4>
        <p id="reset-pin-status" class="secondary-status">Run Option 2 to view output here.</p>
        <p>
          <a id="reset-pin-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="reset-pin-preview" readonly></textarea>
      </section>
    </div>
    </section>

    <section class="tool-panel" data-panel="offboard">

    <h3 class="offboard-h3">Offboard User - Delete all Jabber and Voicemail Box (Option 10)</h3>
    <p>Authentication note: Cisco Callmanager credentials entered below are reused for Unity voicemail and Active Directory actions.</p>

    <div class="offboard-layout">
      <form id="offboard-user-form" class="target-user-form offboard-form" action="javascript:void(0)" method="post" onsubmit="return false;">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to Offboard:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button id="offboard-user-btn" type="button" class="offboard-danger-btn">DANGER: Run Offboard User - Delete all Jabber and Voicemail Box (Option 10)</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="offboard-output" aria-live="polite">
        <h4>Offboard Output Preview</h4>
        <p id="offboard-status" class="offboard-status">Run Offboard User to view output here.</p>
        <p>
          <a id="offboard-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="offboard-preview" readonly></textarea>
      </section>
    </div>

    <script>
      (function () {
        const form = document.getElementById("offboard-user-form");
        const button = document.getElementById("offboard-user-btn");
        const statusEl = document.getElementById("offboard-status");
        const outputEl = document.getElementById("offboard-preview");
        const downloadEl = document.getElementById("offboard-download");

        if (!form || !button || !statusEl || !outputEl || !downloadEl) {
          return;
        }

        async function runOffboard() {
          const targetUserField = form.querySelector('input[name="target_user"]');
          const targetUser = ((targetUserField && targetUserField.value) || "").trim();
          if (!targetUser) {
            statusEl.textContent = "Enter a User ID to offboard.";
            if (targetUserField) {
              targetUserField.focus();
            }
            return;
          }

          const confirmed = confirm(
            `DANGER: This will offboard user "${targetUser}" and remove Jabber devices and voicemail.\n\nDo you want to continue?`
          );
          if (!confirmed) {
            statusEl.textContent = "Offboard action canceled.";
            return;
          }

          statusEl.textContent = "Running Offboard User...";
          outputEl.value = "";
          downloadEl.style.display = "none";
          downloadEl.removeAttribute("href");

          try {
            const formData = new FormData(form);
            const response = await fetch("/decommission/user-csf-voicemail?inline=1", {
              method: "POST",
              body: formData,
              credentials: "same-origin",
            });

            const responseText = await response.text();
            let payload = null;
            try {
              payload = JSON.parse(responseText || "{}");
            } catch (_parseErr) {
              throw new Error(responseText || `Request failed with status ${response.status}`);
            }

            if (!response.ok) {
              throw new Error((payload && payload.detail) || `Request failed with status ${response.status}`);
            }

            outputEl.value = payload.output_text || "";
            statusEl.textContent = `Completed: ${payload.filename || "offboard_output.csv"}`;
            if (payload.download_url) {
              downloadEl.href = payload.download_url;
              downloadEl.style.display = "inline";
            }

            if (targetUserField) {
              targetUserField.value = "";
            }
          } catch (err) {
            statusEl.textContent = "Offboard User failed. Review output and retry.";
            outputEl.value = (err && err.message) ? err.message : "Unknown error.";
          }
        }

        form.addEventListener("submit", function (event) {
          event.preventDefault();
          runOffboard();
        });

        button.addEventListener("click", function (event) {
          event.preventDefault();
          runOffboard();
        });
      })();
    </script>
    </section>

    <section class="tool-panel" data-panel="ad">

    <h3>Update Active Directory Telephone and ipPhone field only (Option 11)</h3>
    <p>Authentication note: Cisco Callmanager credentials entered below are used for Active Directory authentication.</p>

    <div class="ad-update-layout">
      <form id="ad-update-form" class="target-user-form ad-update-form" action="/update/ad-phone-fields" method="post">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to update:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        10-Digit Phone Number (or leave blank to clear):<br>
        <input name="phone_number" placeholder="2145551234" pattern="[0-9]{0,10}"><br><br>

        <div class="action-row">
          <button type="submit">Update AD Phone Fields (Option 11)</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="ad-update-output" aria-live="polite">
        <h4>AD Update Output Preview</h4>
        <p id="ad-update-status" class="ad-update-status">Run Update AD Phone Fields to view output here.</p>
        <p>
          <a id="ad-update-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="ad-update-preview" readonly></textarea>
      </section>
    </div>
    </section>

    <section class="tool-panel" data-panel="tct">

    <h3>Add Secondary Device - Jabber for iPhone (Option 3)</h3>

    <div class="secondary-layout">
      <form id="secondary-tct-form" class="target-user-form secondary-form" action="/add/secondary-tct-device" method="post">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to add secondary iPhone device for:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button type="submit">Run Add Secondary Device - Jabber for iPhone (Option 3)</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="secondary-output" aria-live="polite">
        <h4>Option 3 Output Preview</h4>
        <p id="secondary-tct-status" class="secondary-status">Run Option 3 to view output here.</p>
        <p>
          <a id="secondary-tct-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="secondary-tct-preview" readonly></textarea>
      </section>
    </div>
    </section>

    <section class="tool-panel" data-panel="bot">

    <h3>Add Secondary Device - Jabber for Android (Option 4)</h3>

    <div class="secondary-layout">
      <form id="secondary-bot-form" class="target-user-form secondary-form" action="/add/secondary-bot-device" method="post">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to add secondary Android device for:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button type="submit">Run Add Secondary Device - Jabber for Android (Option 4)</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="secondary-output" aria-live="polite">
        <h4>Option 4 Output Preview</h4>
        <p id="secondary-bot-status" class="secondary-status">Run Option 4 to view output here.</p>
        <p>
          <a id="secondary-bot-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="secondary-bot-preview" readonly></textarea>
      </section>
    </div>
    </section>

    <section class="tool-panel" data-panel="linegroup">

    <h3>Edit Line Group Members (Add/Remove DN) (Option 17)</h3>

    <div class="secondary-layout">
      <form id="line-group-form" class="secondary-form" action="/line-groups/edit-members" method="post">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        Search Line Group Name:<br>
        <input name="line_group_search" placeholder="Example_LineGroup"><br><br>

        <div class="action-row">
          <button type="button" id="line-group-search-btn">Search Line Groups</button>
        </div>
        <p id="line-group-search-status" class="secondary-status">Search first, then choose a matching Line Group.</p>
        <br>

        Select Matching Line Group:<br>
        <select name="line_group_name" required>
          <option value="" selected>Select a Line Group...</option>
        </select><br><br>

        Action:<br>
        <select name="membership_action" required>
          <option value="add" selected>Add DN</option>
          <option value="remove">Remove DN</option>
        </select><br><br>

        Directory Number Pattern:<br>
        <input name="dn_pattern" placeholder="8585236620" required><br><br>

        Route Partition:<br>
        <input name="dn_partition" value="ENT_DEVICE_PT" required><br><br>

        <div class="action-row">
          <button type="submit">Run Edit Line Group Members (Option 17)</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="secondary-output" aria-live="polite">
        <h4>Option 17 Output Preview</h4>
        <p id="line-group-status" class="secondary-status">Run Option 17 to view output here.</p>
        <p>
          <a id="line-group-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="line-group-preview" readonly></textarea>
      </section>
    </div>
    </section>

    <section class="tool-panel" data-panel="jabbernotify">
    <h3>Send Jabber Number/Training Notification</h3>
    <p>Search for an employee by last name, then send them the Cisco Jabber ready email with their telephone number and training link. Use this to test the email or resend it to any user.</p>
    <form id="jabbernotify-form" class="jabber-check-form" style="max-width:520px;">
      <div class="compact-inline-row">
        <span>Cisco Callmanager Username:</span>
        <input name="cucm_user" value="__AUTH_USER__" required>
      </div><br>
      <div class="compact-inline-row">
        <span>Cisco Callmanager Password:</span>
        <input type="password" name="cucm_pass" required>
      </div><br>
      Last Name:<br>
      <input id="jabbernotify-last-name" placeholder="Smith" required style="width:min(280px,100%);"><br><br>
      First Name (optional):<br>
      <input id="jabbernotify-first-name" placeholder="John" style="width:min(280px,100%);"><br><br>
      <div class="action-row">
        <button type="submit">Search</button>
        <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
      </div>
    </form>
    <p id="jabbernotify-search-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
    <div id="jabbernotify-results" style="overflow-x:auto; margin-top:8px;"></div>
    <p id="jabbernotify-send-status" style="margin-top:14px; font-weight:700; min-height:18px;"></p>
    </section>

    <section class="tool-panel" data-panel="mobilejabbernotify">
    <h3>Re-send Jabber Mobile Email Instructions</h3>
    <p>Send the same mobile Jabber instruction email that is sent after Jabber iPhone or Jabber Android is created.</p>
    <form id="mobile-jabber-notify-form" class="jabber-check-form" style="max-width:520px;">
      <div class="compact-inline-row">
        <span>Cisco Callmanager Username:</span>
        <input name="cucm_user" value="__AUTH_USER__" required>
      </div><br>
      <div class="compact-inline-row">
        <span>Cisco Callmanager Password:</span>
        <input type="password" name="cucm_pass" required>
      </div><br>
      User ID:<br>
      <input id="mobile-jabber-target-user" name="target_user" placeholder="john.doe" required style="width:min(280px,100%);"><br><br>
      Telephone Number (optional):<br>
      <input id="mobile-jabber-telephone" name="telephone" placeholder="8585236620" style="width:min(280px,100%);"><br><br>
      <div class="action-row">
        <button type="submit">Send Mobile Instructions</button>
        <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
      </div>
    </form>
    <p id="mobile-jabber-notify-status" style="margin-top:14px; font-weight:700; min-height:18px;"></p>
    </section>

    <section class="tool-panel" data-panel="rebuild">

    <h3>Re-Build Cisco Jabber CSF from Latest Offboard Audit</h3>
    <p>
      This action finds the user's most recent offboard entry in the audit trail and reuses that same extension.
      Rebuild only succeeds when the extension is unassigned and in NOT Active state.
    </p>

    <div class="build-user-layout">
      <form id="rebuild-user-form" class="target-user-form build-user-form" action="/rebuild/user-csf-phone" method="post">
        <div class="compact-inline-row">
          <span>Cisco Callmanager Username:</span>
          <input name="cucm_user" value="__AUTH_USER__" required>
        </div><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to Re-Build Jabber for:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button type="submit">Run Re-Build from Offboard Audit</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="build-user-output" aria-live="polite">
        <h4>Re-Build Output Preview</h4>
        <p id="rebuild-user-status" class="build-user-status">Run Re-Build to view output here.</p>
        <p>
          <a id="rebuild-user-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="rebuild-user-preview" readonly></textarea>
      </section>
    </div>
    </section>

    <script>
      const fieldRules = {
        cucm_user: {
          required: true,
          requiredMessage: "Cisco Callmanager Username is required.",
        },
        cucm_pass: {
          required: true,
          requiredMessage: "Cisco Callmanager Password is required.",
        },
        unity_user: {
          required: true,
          requiredMessage: "Unity Admin Username is required.",
        },
        unity_pass: {
          required: true,
          requiredMessage: "Unity Admin Password is required.",
        },
        target_user: {
          required: true,
          requiredMessage: "User ID is required.",
          pattern: /^[A-Za-z0-9._-]+$/,
          patternMessage: "User ID can only contain letters, numbers, dot, underscore, or hyphen.",
        },
        voicemail_user: {
          required: true,
          requiredMessage: "Voicemail Username is required.",
          pattern: /^[A-Za-z0-9._-]+$/,
          patternMessage: "Voicemail Username can only contain letters, numbers, dot, underscore, or hyphen.",
        },
        new_voicemail_pin: {
          required: true,
          requiredMessage: "New Voicemail PIN is required.",
          pattern: /^\\d{4,20}$/,
          patternMessage: "Voicemail PIN must be numeric and 4-20 digits.",
        },
        confirm_voicemail_pin: {
          required: true,
          requiredMessage: "Confirm Voicemail PIN is required.",
          pattern: /^\\d{4,20}$/,
          patternMessage: "Voicemail PIN must be numeric and 4-20 digits.",
        },
        dn_contains: {
          required: true,
          requiredMessage: "DN Pattern is required.",
        },
        line_group_name: {
          required: true,
          requiredMessage: "Select a Line Group after search.",
        },
        lastname: {
          required: true,
          requiredMessage: "Last Name is required.",
        },
      };

      function clearFieldError(field) {
        const errorEl = field.nextElementSibling;
        if (errorEl && errorEl.classList.contains("field-error")) {
          errorEl.remove();
        }
        field.style.borderColor = "";
      }

      function addFieldError(field, message) {
        clearFieldError(field);
        const errorEl = document.createElement("div");
        errorEl.className = "field-error";
        errorEl.style.color = "#ff8a8a";
        errorEl.style.fontSize = "12px";
        errorEl.style.marginTop = "4px";
        errorEl.textContent = message;
        field.style.borderColor = "#ff6b6b";
        field.insertAdjacentElement("afterend", errorEl);
      }

      function validateForm(form) {
        let firstInvalid = null;
        let hasErrors = false;

        Object.entries(fieldRules).forEach(([fieldName, rule]) => {
          const field = form.querySelector(`[name="${fieldName}"]`);
          if (!field) {
            return;
          }

          const value = (field.value || "").trim();
          clearFieldError(field);

          if (rule.required && !value) {
            addFieldError(field, rule.requiredMessage);
            hasErrors = true;
            if (!firstInvalid) {
              firstInvalid = field;
            }
            return;
          }

          if (rule.pattern && value && !rule.pattern.test(value)) {
            addFieldError(field, rule.patternMessage);
            hasErrors = true;
            if (!firstInvalid) {
              firstInvalid = field;
            }
          }
        });

        if (firstInvalid) {
          firstInvalid.focus();
        }

        return !hasErrors;
      }

      function validatePinConfirmation(form) {
        const newPinField = form.querySelector('[name="new_voicemail_pin"]');
        const confirmPinField = form.querySelector('[name="confirm_voicemail_pin"]');
        if (!newPinField || !confirmPinField) {
          return true;
        }

        clearFieldError(confirmPinField);
        if ((newPinField.value || "") !== (confirmPinField.value || "")) {
          addFieldError(confirmPinField, "Voicemail PIN values must match.");
          confirmPinField.focus();
          return false;
        }

        return true;
      }

      async function submitBuildUserInline(form) {
        const statusEl = document.getElementById("build-user-status");
        const outputEl = document.getElementById("build-user-preview");
        const downloadEl = document.getElementById("build-user-download");

        statusEl.textContent = "Running Build User...";
        outputEl.value = "";
        downloadEl.style.display = "none";
        downloadEl.removeAttribute("href");

        try {
          const formData = new FormData(form);
          const response = await fetch(`${form.action}?inline=1`, {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          outputEl.value = result.output_text || "";
          statusEl.textContent = `Completed: ${result.filename || "build_user_output.csv"}`;
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          const targetUserInput = form.querySelector('input[name="target_user"]');
          if (targetUserInput) {
            targetUserInput.value = "";
          }
        } catch (error) {
          statusEl.textContent = "Build User failed. Review output and retry.";
          outputEl.value = error.message || "Unknown error.";
        }
      }

      async function submitResetPinInline(form) {
        const statusEl = document.getElementById("reset-pin-status");
        const outputEl = document.getElementById("reset-pin-preview");
        const downloadEl = document.getElementById("reset-pin-download");

        statusEl.textContent = "Running Option 2...";
        outputEl.value = "";
        downloadEl.style.display = "none";
        downloadEl.removeAttribute("href");

        try {
          const formData = new FormData(form);
          const response = await fetch(`${form.action}?inline=1`, {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          outputEl.value = result.output_text || "";
          statusEl.textContent = `Completed: ${result.filename || "option2_output.csv"}`;
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          const voicemailUserInput = form.querySelector('input[name="voicemail_user"]');
          const newPinInput = form.querySelector('input[name="new_voicemail_pin"]');
          const confirmPinInput = form.querySelector('input[name="confirm_voicemail_pin"]');
          if (voicemailUserInput) voicemailUserInput.value = "";
          if (newPinInput) newPinInput.value = "";
          if (confirmPinInput) confirmPinInput.value = "";
        } catch (error) {
          statusEl.textContent = "Option 2 failed. Review output and retry.";
          outputEl.value = error.message || "Unknown error.";
        }
      }

      async function submitOffboardInline(form) {
        const statusEl = document.getElementById("offboard-status");
        const outputEl = document.getElementById("offboard-preview");
        const downloadEl = document.getElementById("offboard-download");
        const targetUserInput = form.querySelector('input[name="target_user"]');
        const targetUser = ((targetUserInput && targetUserInput.value) || "").trim();

        const confirmed = confirm(
          `DANGER: This will offboard user "${targetUser}" and remove Jabber devices and voicemail.\n\nDo you want to continue?`
        );
        if (!confirmed) {
          statusEl.textContent = "Offboard action canceled.";
          return;
        }

        statusEl.textContent = "Running Offboard User...";
        outputEl.value = "";
        downloadEl.style.display = "none";
        downloadEl.removeAttribute("href");

        try {
          const formData = new FormData(form);
          const response = await fetch(`${form.action}?inline=1`, {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          outputEl.value = result.output_text || "";
          statusEl.textContent = `Completed: ${result.filename || "offboard_output.csv"}`;
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          if (targetUserInput) {
            targetUserInput.value = "";
          }
        } catch (error) {
          statusEl.textContent = "Offboard User failed. Review output and retry.";
          outputEl.value = error.message || "Unknown error.";
        }
      }

      async function submitSecondaryInline(form, config) {
        const statusEl = document.getElementById(config.statusId);
        const outputEl = document.getElementById(config.previewId);
        const downloadEl = document.getElementById(config.downloadId);

        statusEl.textContent = config.runningText;
        outputEl.value = "";
        downloadEl.style.display = "none";
        downloadEl.removeAttribute("href");

        try {
          const formData = new FormData(form);
          const response = await fetch(`${form.action}?inline=1`, {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          outputEl.value = result.output_text || "";
          statusEl.textContent = `Completed: ${result.filename || config.defaultFilename}`;
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          const targetUserInput = form.querySelector('input[name="target_user"]');
          if (targetUserInput) {
            targetUserInput.value = "";
          }
        } catch (error) {
          statusEl.textContent = config.failedText;
          outputEl.value = error.message || "Unknown error.";
        }
      }

      async function submitAdUpdateInline(form) {
        const statusEl = document.getElementById("ad-update-status");
        const outputEl = document.getElementById("ad-update-preview");
        const downloadEl = document.getElementById("ad-update-download");
        const phoneField = form.querySelector('input[name="phone_number"]');
        const userField = form.querySelector('input[name="target_user"]');

        const phoneValue = (phoneField.value || "").trim();

        if (!phoneValue) {
          const username = (userField.value || "").trim();
          const confirmed = confirm(
            `Are you sure you want to clear the phone field for "${username}"?`
          );
          if (!confirmed) {
            return;
          }
        }

        statusEl.textContent = "Running AD Phone Field Update...";
        outputEl.value = "";
        downloadEl.style.display = "none";
        downloadEl.removeAttribute("href");

        try {
          const formData = new FormData(form);
          const response = await fetch(`${form.action}?inline=1`, {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          outputEl.value = result.output_text || "";
          statusEl.textContent = `Completed: ${result.filename || "ad_update_output.csv"}`;
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          userField.value = "";
          phoneField.value = "";
        } catch (error) {
          statusEl.textContent = "AD Phone Field Update failed. Review output and retry.";
          outputEl.value = error.message || "Unknown error.";
        }
      }

      async function searchLineGroups(form) {
        const searchStatusEl = document.getElementById("line-group-search-status");
        const selectEl = form.querySelector('select[name="line_group_name"]');

        searchStatusEl.textContent = "Searching Line Groups...";

        while (selectEl.options.length > 1) {
          selectEl.remove(1);
        }
        selectEl.value = "";

        try {
          const formData = new FormData(form);
          const response = await fetch("/line-groups/search", {
            method: "POST",
            body: formData,
          });

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Request failed with status ${response.status}`);
          }

          const result = await response.json();
          const matches = result.matches || [];

          if (!matches.length) {
            searchStatusEl.textContent = "No matching Line Groups found.";
            return;
          }

          matches.forEach((name) => {
            const opt = document.createElement("option");
            opt.value = name;
            opt.textContent = name;
            selectEl.appendChild(opt);
          });

          if (matches.length === 1) {
            selectEl.value = matches[0];
          }

          searchStatusEl.textContent = `Found ${matches.length} matching Line Group(s).`;
        } catch (error) {
          searchStatusEl.textContent = `Search failed: ${error.message || "Unknown error."}`;
        }
      }

      document.querySelectorAll("form").forEach((form) => {

        form.querySelectorAll("input").forEach((field) => {
          field.addEventListener("input", () => clearFieldError(field));
        });

        form.addEventListener("submit", (event) => {
          if (!validateForm(form)) {
            event.preventDefault();
            return;
          }

          if (!validatePinConfirmation(form)) {
            event.preventDefault();
            return;
          }

          if (form.id === "build-user-form") {
            event.preventDefault();
            checkForDuplicateDevices(form, ["csf"]).then((proceed) => {
              if (proceed) submitBuildUserInline(form);
            });
            return;
          }

          if (form.id === "reset-pin-form") {
            event.preventDefault();
            submitResetPinInline(form);
            return;
          }

          if (form.id === "offboard-user-form") {
            event.preventDefault();
            submitOffboardInline(form);
            return;
          }

          if (form.id === "ad-update-form") {
            event.preventDefault();
            submitAdUpdateInline(form);
            return;
          }

          if (form.id === "called-name-form") {
            event.preventDefault();
            submitSecondaryInline(form, {
              statusId: "called-name-status",
              previewId: "called-name-preview",
              downloadId: "called-name-download",
              runningText: "Running Employee Name Change-Update Jabber/VM...",
              failedText: "Employee Name Change-Update Jabber/VM failed. Review output and retry.",
              defaultFilename: "called_name_change_output.csv",
            });
            return;
          }

          if (form.id === "rebuild-user-form") {
            event.preventDefault();
            submitSecondaryInline(form, {
              statusId: "rebuild-user-status",
              previewId: "rebuild-user-preview",
              downloadId: "rebuild-user-download",
              runningText: "Running Re-Build from Offboard Audit...",
              failedText: "Re-Build failed. Review output and retry.",
              defaultFilename: "rebuild_user_csf_phone_output.csv",
            });
            return;
          }

          if (form.id === "secondary-tct-form") {
            event.preventDefault();
            checkForDuplicateDevices(form, ["tct"]).then((proceed) => {
              if (proceed) submitSecondaryInline(form, {
                statusId: "secondary-tct-status",
                previewId: "secondary-tct-preview",
                downloadId: "secondary-tct-download",
                runningText: "Running Option 3...",
                failedText: "Option 3 failed. Review output and retry.",
                defaultFilename: "option3_output.csv",
              });
            });
            return;
          }

          if (form.id === "secondary-bot-form") {
            event.preventDefault();
            checkForDuplicateDevices(form, ["bot"]).then((proceed) => {
              if (proceed) submitSecondaryInline(form, {
                statusId: "secondary-bot-status",
                previewId: "secondary-bot-preview",
                downloadId: "secondary-bot-download",
                runningText: "Running Option 4...",
                failedText: "Option 4 failed. Review output and retry.",
                defaultFilename: "option4_output.csv",
              });
            });
            return;
          }

          if (form.id === "secondary-strike-form") {
            event.preventDefault();
            checkForDuplicateDevices(form, ["tct", "bot"]).then((proceed) => {
              if (proceed) submitSecondaryInline(form, {
                statusId: "secondary-strike-status",
                previewId: "secondary-strike-preview",
                downloadId: "secondary-strike-download",
                runningText: "Running Option 5...",
                failedText: "Option 5 failed. Review output and retry.",
                defaultFilename: "option5_output.csv",
              });
            });
            return;
          }

          if (form.id === "line-group-form") {
            event.preventDefault();
            submitSecondaryInline(form, {
              statusId: "line-group-status",
              previewId: "line-group-preview",
              downloadId: "line-group-download",
              runningText: "Running Option 17...",
              failedText: "Option 17 failed. Review output and retry.",
              defaultFilename: "option17_output.csv",
            });
            return;
          }

          if (form.id === "rpo-form") {
            event.preventDefault();
            submitSecondaryInline(form, {
              statusId: "rpo-status",
              previewId: "rpo-preview",
              downloadId: "rpo-download",
              runningText: "Running Option 18...",
              failedText: "Option 18 failed. Review output and retry.",
              defaultFilename: "option18_output.csv",
            });
            return;
          }

          const targetUserInput = form.querySelector('input[name="target_user"]');
          if (targetUserInput) {
            setTimeout(() => {
              targetUserInput.value = "";
            }, 0);
          }
        });
      });

      const lineGroupForm = document.getElementById("line-group-form");
      const lineGroupSearchBtn = document.getElementById("line-group-search-btn");
      if (lineGroupForm && lineGroupSearchBtn) {
        lineGroupSearchBtn.addEventListener("click", () => {
          searchLineGroups(lineGroupForm);
        });
      }

      // ── Jabber Notify panel (Page 1) ──────────────────────────────────────
      (function () {
        var jnForm = document.getElementById("jabbernotify-form");
        var jnStatus = document.getElementById("jabbernotify-search-status");
        var jnResults = document.getElementById("jabbernotify-results");
        var jnSendStatus = document.getElementById("jabbernotify-send-status");
        if (!jnForm || !jnStatus || !jnResults) return;
        jnForm.addEventListener("submit", async function (event) {
          event.preventDefault();
          jnStatus.textContent = "Searching...";
          jnResults.innerHTML = "";
          if (jnSendStatus) jnSendStatus.textContent = "";
          var userField = jnForm.querySelector('input[name="cucm_user"]');
          var passField = jnForm.querySelector('input[name="cucm_pass"]');
          var lastNameEl = document.getElementById("jabbernotify-last-name");
          var firstNameEl = document.getElementById("jabbernotify-first-name");
          var lastName = ((lastNameEl && lastNameEl.value) || "").trim();
          var firstName = ((firstNameEl && firstNameEl.value) || "").trim();
          var cucmUser = ((userField && userField.value) || "").trim();
          var cucmPass = (passField && passField.value) || "";
          if (!lastName) { jnStatus.textContent = "Last Name is required."; return; }
          if (!cucmUser || !cucmPass) { jnStatus.textContent = "Enter CUCM credentials first."; return; }
          try {
            var fd = new FormData();
            fd.append("cucm_user", cucmUser);
            fd.append("cucm_pass", cucmPass);
            fd.append("last_name", lastName);
            fd.append("first_name", firstName);
            var resp = await fetch("/lookup/person", { method: "POST", body: fd, credentials: "same-origin", headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" } });
            var payload = await resp.json();
            if (!resp.ok || !payload.ok) throw new Error((payload && payload.detail) || "Search failed.");
            var results = payload.results || [];
            if (!results.length) { jnStatus.textContent = "No users found."; return; }
            jnStatus.textContent = "Found " + results.length + " user(s). Click Send Notification to email a user.";
            var html = '<table style="width:100%; border-collapse:collapse; font-size:13px;"><thead><tr style="background:#005eb8; color:#fff;">';
            html += '<th style="padding:8px 10px; text-align:left;">Name</th><th style="padding:8px 10px; text-align:left;">User ID</th><th style="padding:8px 10px; text-align:left;">Telephone</th><th style="padding:8px 10px; text-align:left;">Email</th><th style="padding:8px 10px; text-align:left;">Action</th></tr></thead><tbody>';
            results.forEach(function (r, i) {
              var bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
              var uid = r.userid || "";
              var name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || uid;
              var tel = r.telephone || "\u2014";
              var email = r.email || "\u2014";
              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;"><td style="padding:7px 10px;">' + name + '</td><td style="padding:7px 10px;">' + uid + '</td><td style="padding:7px 10px;">' + tel + '</td><td style="padding:7px 10px;">' + email + '</td><td style="padding:7px 10px;"><button type="button" data-nuid="' + uid + '" data-ntel="' + (r.telephone || "") + '" style="background:#237741;color:#fff;border:none;border-radius:6px;padding:6px 12px;font-weight:700;cursor:pointer;">Send Notification</button></td></tr>';
            });
            html += '</tbody></table>';
            jnResults.innerHTML = html;
            jnResults.querySelectorAll('button[data-nuid]').forEach(function (btn) {
              btn.addEventListener("click", async function () {
                var uid = btn.getAttribute("data-nuid") || "";
                var tel = btn.getAttribute("data-ntel") || "";
                if (jnSendStatus) jnSendStatus.textContent = "Sending...";
                btn.disabled = true;
                try {
                  var sf = new FormData();
                  sf.append("cucm_user", cucmUser);
                  sf.append("cucm_pass", cucmPass);
                  sf.append("target_user", uid);
                  sf.append("telephone", tel);
                  var sr = await fetch("/send/jabber-ready-email", { method: "POST", body: sf, credentials: "same-origin", headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" } });
                  var sp = await sr.json();
                  if (!sr.ok || !sp.ok) throw new Error((sp && sp.detail) || "Send failed.");
                  if (jnSendStatus) jnSendStatus.textContent = "Sent: " + (sp.detail || "Email sent successfully.");
                } catch (err) {
                  if (jnSendStatus) jnSendStatus.textContent = "Failed: " + ((err && err.message) || "Unknown error.");
                  btn.disabled = false;
                }
              });
            });
          } catch (err) {
            jnStatus.textContent = "Search error: " + ((err && err.message) || "Unknown.");
          }
        });
      })();
      // ── End Jabber Notify panel ──────────────────────────────────────

      // ── Mobile Jabber Notify panel (Page 1) ──────────────────────────
      (function () {
        var form = document.getElementById("mobile-jabber-notify-form");
        var statusEl = document.getElementById("mobile-jabber-notify-status");
        if (!form || !statusEl) return;
        form.addEventListener("submit", async function (event) {
          event.preventDefault();
          var userField = form.querySelector('input[name="cucm_user"]');
          var passField = form.querySelector('input[name="cucm_pass"]');
          var targetField = form.querySelector('input[name="target_user"]');
          var phoneField = form.querySelector('input[name="telephone"]');
          var cucmUser = ((userField && userField.value) || "").trim();
          var cucmPass = (passField && passField.value) || "";
          var targetUser = ((targetField && targetField.value) || "").trim();
          var telephone = ((phoneField && phoneField.value) || "").trim();

          if (!cucmUser || !cucmPass) {
            statusEl.textContent = "Enter CUCM credentials first.";
            return;
          }
          if (!targetUser) {
            statusEl.textContent = "User ID is required.";
            return;
          }

          statusEl.textContent = "Sending...";
          try {
            var fd = new FormData();
            fd.append("cucm_user", cucmUser);
            fd.append("cucm_pass", cucmPass);
            fd.append("target_user", targetUser);
            fd.append("telephone", telephone);
            var resp = await fetch("/send/mobile-jabber-email", {
              method: "POST",
              body: fd,
              credentials: "same-origin",
              headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
            });
            var payload = await resp.json();
            if (!resp.ok || !payload.ok) {
              throw new Error((payload && payload.detail) || "Send failed.");
            }
            statusEl.textContent = "Sent: " + (payload.detail || "Mobile email sent successfully.");
          } catch (err) {
            statusEl.textContent = "Failed: " + ((err && err.message) || "Unknown error.");
          }
        });
      })();
      // ── End Mobile Jabber Notify panel ───────────────────────────────

      const navButtons = Array.from(document.querySelectorAll(".portal-nav-btn"));
      const panels = Array.from(document.querySelectorAll(".tool-panel"));

      function showPanel(panelKey) {
        panels.forEach((panel) => {
          const isActive = panel.dataset.panel === panelKey;
          panel.classList.toggle("active", isActive);
        });

        navButtons.forEach((btn) => {
          btn.classList.toggle("active", btn.dataset.panel === panelKey);
        });
      }

      // Globally accessible so inline onclick handlers in dynamic tables can call it.
      window.prefillPanel = function (panelKey, userId, telephone) {
        showPanel(panelKey);
        const panel = panels.find((p) => p.dataset.panel === panelKey);
        if (!panel) return;
        const targetField = panel.querySelector('input[name="target_user"]');
        if (targetField) {
          targetField.value = userId || "";
        }
        const telephoneField = panel.querySelector('input[name="telephone"]');
        if (telephoneField) {
          telephoneField.value = telephone || "";
        }
        // Scroll panel into view
        panel.scrollIntoView({ behavior: "smooth", block: "start" });
      };

      navButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
          showPanel(btn.dataset.panel);
        });
      });

      // Allow deep-linking from /menu-admin menu buttons into specific /menu panels.
      const qs = new URLSearchParams(window.location.search);
      const initialPanel = (qs.get("panel") || "").trim();
      if (initialPanel && panels.some((panel) => panel.dataset.panel === initialPanel)) {
        showPanel(initialPanel);
      }

      const initialTargetUser = (qs.get("target_user") || "").trim();
      if (initialTargetUser) {
        const targetPanel = initialPanel
          ? panels.find((panel) => panel.dataset.panel === initialPanel)
          : null;
        if (targetPanel) {
          const targetField = targetPanel.querySelector('input[name="target_user"]');
          if (targetField) {
            targetField.value = initialTargetUser;
          }
        }
      }



      // ── Duplicate device pre-check ──────────────────────────────────────────
      // Runs before Build CSF, TCT, BOT, and Strike forms submit.
      // Calls /check/user-devices, warns if the relevant device type already exists.

      async function checkForDuplicateDevices(form, deviceTypes) {
        const targetField = form.querySelector('input[name="target_user"]');
        const userField = form.querySelector('input[name="cucm_user"]');
        const passField = form.querySelector('input[name="cucm_pass"]');
        if (!targetField || !userField || !passField) return true;

        const targetUser = (targetField.value || "").trim();
        if (!targetUser) return true;

        const checkData = new FormData();
        checkData.append("cucm_user", userField.value || "");
        checkData.append("cucm_pass", passField.value || "");
        checkData.append("target_user", targetUser);

        let result;
        try {
          const resp = await fetch("/check/user-devices", {
            method: "POST",
            body: checkData,
            credentials: "same-origin",
          });
          result = await resp.json();
        } catch (_err) {
          // Network/auth error — don't block, let the main action surface it.
          return true;
        }

        if (!result || !result.ok) return true;

        const found = [];
        if (deviceTypes.includes("csf") && result.has_csf) found.push("CSF (Jabber Laptop)");
        if (deviceTypes.includes("tct") && result.has_tct) found.push("TCT (Jabber iPhone)");
        if (deviceTypes.includes("bot") && result.has_bot) found.push("BOT (Jabber Android)");

        if (!found.length) return true;

        const displayName = result.display_name ? ` (${result.display_name})` : "";
        return confirm(
          `Duplicate device warning\\n\\nUser "${targetUser}"${displayName} already has:\\n  • ${found.join("\\n  • ")}\\n\\nDo you want to continue anyway?`
        );
      }

    </script>
      </section>
    </div>
    </main>
  </body>
</html>
""".replace("__AUTH_USER__", auth_user).replace("__ENV_TEXT__", escape(env_text)).replace("__ENV_CLASS__", env_css_class).replace("__ADMIN_CARD__", admin_card_html)

  return HTMLResponse(
    content=html,
    headers={
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "Pragma": "no-cache",
      "Expires": "0",
    },
  )


@app.get("/menu-admin", response_class=HTMLResponse)
def menu_admin_page(request: Request):
  session = _get_auth_session(request) or {}
  session_username = str(session.get("username", ""))
  if not _is_admin_user(session_username):
    return HTMLResponse(
      content="<h3>403 Forbidden</h3><p>You are not authorized to access Administrative Items.</p>",
      status_code=403,
    )

  auth_user = escape(session_username)
  auth_cucm_host = str(session.get("cucm_host", ""))
  env_text, env_css_class = _get_environment_label(auth_cucm_host)

  html = """
<html>
  <head>
    <title>Administrative Items - Voice Operations Portal</title>
    <style>
      :root {
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-sky: #eaf4ff;
        --amn-ice: #f6fbff;
        --amn-gold: #c68a12;
        --amn-text: #12304a;
        --amn-text-soft: #4e6a84;
        --amn-border: #c8dbee;
        --amn-panel-border: rgba(0, 47, 108, 0.12);
        --amn-shadow: 0 14px 30px rgba(0, 47, 108, 0.11);
      }

      body {
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        margin: 0;
        background:
          radial-gradient(circle at top left, rgba(0, 94, 184, 0.18), transparent 26%),
          radial-gradient(circle at top right, rgba(198, 138, 18, 0.16), transparent 22%),
          linear-gradient(180deg, #f4f9fe 0%, #e8f1f9 42%, #edf5fc 100%);
        color: var(--amn-text);
      }

      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 16px 28px;
        background: linear-gradient(120deg, rgba(0, 47, 108, 0.98), rgba(0, 94, 184, 0.94));
        color: #fff;
        box-shadow: 0 12px 28px rgba(0, 47, 108, 0.2);
        border-bottom: 1px solid rgba(255, 255, 255, 0.16);
      }

      .brand-fallback {
        font-weight: 700;
        letter-spacing: 0.6px;
        text-transform: uppercase;
        font-size: 12px;
        opacity: 0.86;
      }

      .content {
        max-width: 1200px;
        margin: 16px auto 22px auto;
        padding: 0 16px 16px 16px;
      }

      .page-hero {
        position: relative;
        overflow: hidden;
        padding: 20px 22px;
        margin-bottom: 14px;
        border-radius: 18px;
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.96), rgba(239, 247, 255, 0.95));
        border: 1px solid rgba(0, 47, 108, 0.1);
        box-shadow: var(--amn-shadow);
      }

      .page-hero::after {
        content: "";
        position: absolute;
        right: -60px;
        top: -50px;
        width: 240px;
        height: 240px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(0, 94, 184, 0.18), transparent 68%);
        pointer-events: none;
      }

      .page-kicker {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 7px 12px;
        border-radius: 999px;
        background: rgba(0, 94, 184, 0.08);
        color: var(--amn-blue);
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 0.4px;
        text-transform: uppercase;
      }

      .page-title-row {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 18px;
        flex-wrap: wrap;
        margin-top: 14px;
      }

      .page-title {
        margin: 0;
        color: var(--amn-navy);
        font-size: 27px;
        line-height: 1.1;
      }

      .page-subtitle {
        margin: 10px 0 0 0;
        color: var(--amn-text-soft);
        font-size: 14px;
        line-height: 1.55;
        max-width: 720px;
      }

      .page-meta-card {
        min-width: 230px;
        padding: 14px 16px;
        border-radius: 14px;
        background: linear-gradient(180deg, rgba(0, 47, 108, 0.96), rgba(0, 94, 184, 0.92));
        color: #fff;
        box-shadow: 0 14px 28px rgba(0, 47, 108, 0.22);
      }

      .page-meta-label {
        display: block;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.5px;
        opacity: 0.76;
        text-transform: uppercase;
      }

      .page-meta-value {
        display: block;
        margin-top: 6px;
        font-size: 18px;
        font-weight: 700;
      }

      .page-meta-note {
        margin: 10px 0 0 0;
        font-size: 13px;
        line-height: 1.5;
        color: rgba(255, 255, 255, 0.86);
      }

      .hero-link-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 10px;
        margin-top: 14px;
      }

      .hero-link-card {
        display: block;
        padding: 12px 14px;
        border-radius: 12px;
        background: rgba(255, 255, 255, 0.9);
        border: 1px solid rgba(0, 47, 108, 0.1);
        color: inherit;
        text-decoration: none;
        box-shadow: 0 10px 20px rgba(0, 47, 108, 0.06);
        transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
      }

      .hero-link-card:hover {
        transform: translateY(-2px);
        border-color: rgba(0, 94, 184, 0.3);
        box-shadow: 0 14px 28px rgba(0, 47, 108, 0.11);
      }

      .hero-link-card strong {
        display: block;
        color: var(--amn-navy);
        margin-bottom: 5px;
      }

      .hero-link-card span {
        display: block;
        font-size: 13px;
        color: var(--amn-text-soft);
        line-height: 1.5;
      }

      .env-banner {
        display: inline-block;
        margin: 8px 0 0 0;
        padding: 10px 16px;
        border-radius: 10px;
        font-weight: 800;
        letter-spacing: 0.2px;
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.3);
      }

      .env-banner-prod {
        color: #083252;
        background: #d8ecff;
        border: 1px solid #8bb9e2;
      }

      .env-banner-lab {
        color: #5c2700;
        background: #ffe6cc;
        border: 1px solid #f7b267;
      }

      .portal-shell {
        display: grid;
        grid-template-columns: 300px minmax(0, 1fr);
        gap: 18px;
        align-items: start;
      }

      .portal-sidebar {
        position: sticky;
        top: 18px;
        background: rgba(255, 255, 255, 0.94);
        border: 1px solid rgba(0, 47, 108, 0.12);
        border-radius: 14px;
        box-shadow: var(--amn-shadow);
        padding: 12px;
      }

      .portal-sidebar h4 {
        margin: 4px 0 10px 2px;
        color: var(--amn-navy);
      }

      .portal-nav {
        display: grid;
        gap: 8px;
      }

      .portal-nav-btn {
        text-align: left;
        width: 100%;
        border-radius: 10px;
        border: 1px solid rgba(0, 47, 108, 0.14);
        background: rgba(255, 255, 255, 0.92);
        color: #0d3150;
        padding: 10px 11px;
        font-weight: 700;
        cursor: pointer;
        box-shadow: none;
      }

      .portal-nav-btn:hover {
        background: #f3f9ff;
        border-color: rgba(0, 94, 184, 0.3);
        transform: translateY(-1px);
      }

      .portal-nav-btn.active {
        background: linear-gradient(180deg, #0c77d8, #005eb8);
        color: #fff;
        border-color: rgba(0, 94, 184, 0.45);
      }

      .portal-main {
        min-width: 0;
      }

      .tool-panel {
        display: none;
      }

      .tool-panel.active {
        display: block;
      }

      .panel {
        background: rgba(255, 255, 255, 0.93);
        border: 1px solid var(--amn-panel-border);
        border-radius: 14px;
        padding: 14px;
        box-shadow: var(--amn-shadow);
        backdrop-filter: blur(6px);
        margin: 0 0 18px 0;
      }

      h3 {
        margin: 6px 0 10px 0;
        color: var(--amn-navy);
        font-size: 20px;
      }

      input,
      textarea,
      button {
        border-radius: 10px;
        border: 1px solid var(--amn-border);
      }

      input,
      textarea {
        min-height: 36px;
        padding: 7px 10px;
        width: min(700px, 100%);
        background: rgba(255, 255, 255, 0.96);
      }

      form input[name="cucm_user"],
      form input[name="cucm_pass"] {
        width: min(130px, 100%);
      }

      .compact-inline-row {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }

      .compact-inline-row span {
        display: inline-block;
        width: 220px;
        font-weight: 600;
      }

      input:focus,
      textarea:focus {
        outline: none;
        border-color: rgba(0, 94, 184, 0.55);
        box-shadow: 0 0 0 4px rgba(0, 94, 184, 0.12);
      }

      button {
        background: linear-gradient(180deg, #0c77d8, #005eb8);
        color: #fff;
        border: none;
        padding: 9px 13px;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 8px 18px rgba(0, 94, 184, 0.16);
        transition: transform 0.18s ease, box-shadow 0.18s ease, filter 0.18s ease;
      }

      button:hover {
        filter: brightness(1.04);
        transform: translateY(-1px);
        box-shadow: 0 12px 22px rgba(0, 94, 184, 0.2);
      }

      a {
        color: var(--amn-blue);
        font-weight: 700;
      }

      @media (max-width: 980px) {
        .topbar {
          padding: 14px 16px;
        }

        .compact-inline-row span {
          width: auto;
        }

        .page-hero {
          padding: 16px 14px;
        }

        .page-title {
          font-size: 23px;
        }

        .portal-shell {
          grid-template-columns: 1fr;
        }

        .portal-sidebar {
          position: static;
        }
      }
    </style>
  </head>
  <body>
    <header class="topbar">
      <span class="brand-fallback">AMN Healthcare</span>
      <strong>Voice Operations Portal - Administrative Items</strong>
    </header>

    <main class="content">
      <section class="page-hero">
        <span class="page-kicker">Administrative Workbench</span>
        <div class="page-title-row">
          <div>
            <h2 class="page-title">Administrative Items</h2>
            <p class="page-subtitle">Bulk operations, strike workflows, export utilities, and translation lookups in a single workspace for higher-volume admin work.</p>
            <div class="env-banner __ENV_CLASS__">__ENV_TEXT__</div>
          </div>
          <aside class="page-meta-card">
            <span class="page-meta-label">Authenticated Operator</span>
            <span class="page-meta-value">__AUTH_USER__</span>
            <p class="page-meta-note">Use the main operations menu for day-to-day actions. This page is focused on advanced and bulk administration.</p>
          </aside>
        </div>
        <div class="hero-link-grid">
          <a class="hero-link-card" href="/menu">
            <strong>Main Operations</strong>
            <span>Return to standard user-facing voice operations workflows.</span>
          </a>
          <a class="hero-link-card" href="/download/audit-trail">
            <strong>Audit Trail CSV</strong>
            <span>Download logged portal activity and execution history.</span>
          </a>
        </div>
      </section>

      <div class="portal-shell">
        <aside class="portal-sidebar">
          <h4>Administrative Menu</h4>
          <div class="portal-nav">
            <button type="button" class="portal-nav-btn active" data-panel="personlookup">Employee Lookup by Name</button>
            <button type="button" class="portal-nav-btn" data-panel="strike">Strike Mode - Add iPhone and Android</button>
            <button type="button" class="portal-nav-btn" data-panel="mobiledelete">Remove only Jabber Mobile</button>
            <button type="button" class="portal-nav-btn" data-panel="rpo">Extract RPO Phones</button>
            <button type="button" class="portal-nav-btn" data-panel="adddn">Add Directory Numbers (CSV)</button>
            <button type="button" class="portal-nav-btn" data-panel="exportdn">Export Directory Numbers</button>
            <button type="button" class="portal-nav-btn" data-panel="exportusers">Export End Users</button>
            <button type="button" class="portal-nav-btn" data-panel="translookup">Translation Pattern Lookup</button>
            <button type="button" class="portal-nav-btn" data-panel="transtemplate">Translation Pattern Template</button>
            <button type="button" class="portal-nav-btn" onclick="window.location.href='/menu?panel=teams-telephony'">Create Teams Telephony User (Main Ops)</button>
            <button type="button" class="portal-nav-btn portal-nav-btn-danger" onclick="window.location.href='/menu?panel=teams-telephony-remove'">Remove Teams Telephony User (Main Ops)</button>
            <button type="button" class="portal-nav-btn portal-nav-btn-danger" onclick="window.location.href='/menu?panel=offboard'">Separate Employeed-Delete Jabber/VM (Main Ops)</button>
            <button type="button" class="portal-nav-btn" onclick="window.location.href='/menu?panel=linegroup'">Update Hunt List Line Group (Main Ops)</button>
            <button type="button" class="portal-nav-btn" data-panel="jabbernotify">Send Jabber Number/Training Notification</button>
            <button type="button" class="portal-nav-btn" data-panel="bulkperson">Bulk Person Lookup (CSV)</button>
            <button type="button" class="portal-nav-btn" data-panel="bulkextension">Bulk Extension Lookup (CSV)</button>
          </div>
        </aside>

        <section class="portal-main">

      <section class="panel tool-panel active" data-panel="personlookup">
        <h3>Employee Lookup by Name</h3>
        <p>Search by last name (optional first name), then use the result to prefill Strike Mode.</p>
        <form id="admin-person-lookup-form">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          Last Name:<br>
          <input name="last_name" placeholder="Smith" required><br><br>

          First Name (optional):<br>
          <input name="first_name" placeholder="John"><br><br>

          <button type="submit">Search</button>
        </form>

        <p id="admin-person-lookup-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
        <div id="admin-person-lookup-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="strike">
        <h3>Strike Mode - Add in both Jabber iPhone and Android (Option 5)</h3>
        <form id="admin-strike-form" action="/add/secondary-strike-devices" method="post">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          User ID for person to add STRIKE MODE devices for:<br>
          <input id="admin-strike-target-user" name="target_user" placeholder="john.doe" required><br><br>

          <button type="submit">Run STRIKE MODE</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="mobiledelete">
        <h3>Remove only Jabber Mobile - iPhone or Android</h3>
        <p>Lookup by last name, then remove Jabber iPhone (TCT), Jabber Android (BOT), or both. This does not delete CSF or voicemail.</p>
        <form id="admin-mobile-delete-lookup-form">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          Last Name:<br>
          <input name="last_name" placeholder="Smith" required><br><br>

          First Name (optional):<br>
          <input name="first_name" placeholder="John"><br><br>

          <button type="submit">Search Users for Mobile Delete</button>
        </form>

        <p id="admin-mobile-delete-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
        <div id="admin-mobile-delete-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="rpo">
        <h3>Extract RPO Phones (Option 18)</h3>
        <form action="/export/rpo-phones" method="post">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          User IDs (one per line):<br>
          <textarea name="rpo_userids" rows="8" placeholder="john.doe&#10;jane.smith" required></textarea><br><br>

          <button type="submit">Run Extract RPO Phones</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="adddn">
        <h3>Add Directory Numbers (Upload CSV)</h3>
        <form action="/add/directorynumbers" method="post" enctype="multipart/form-data">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          CSV File:<br>
          <input type="file" name="csv_file" required><br><br>

          <a href="/download/add-directorynumbers-template">Download CSV Template</a><br><br>

          <button type="submit">Run Add Directory Numbers</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="exportdn">
        <h3>Export Directory Numbers</h3>
        <form action="/export/directorynumbers" method="post">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          DN Pattern (supports %):<br>
          <input name="dn_contains"><br><br>

          Route Partition (optional):<br>
          <input name="route_partition"><br><br>

          <button type="submit">Export Directory Numbers</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="exportusers">
        <h3>Export End Users</h3>
        <form action="/export/endusers" method="post">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          Last Name:<br>
          <input name="lastname" required><br><br>

          <button type="submit">Export End Users</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="translookup">
        <h3>Translation Pattern Lookup</h3>
        <p>Search translation patterns and return pattern, description, and called party transform mask.</p>
        <form id="admin-trans-pattern-form">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          Pattern contains:<br>
          <input name="pattern_query" placeholder="55512" required><br><br>

          <button type="submit">Search Translation Patterns</button>
        </form>

        <p id="admin-trans-pattern-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a pattern and click Search.</p>
        <div id="admin-trans-pattern-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="transtemplate">
        <h3>Translation Pattern Template From Example</h3>
        <p>Start with the example that begins with <strong>3148984689</strong>. The template keeps everything the same except the Translation Pattern and Description.</p>
        <form id="admin-trans-template-form">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          Example starts with:<br>
          <input name="pattern_prefix" value="3148984689" required><br><br>

          <button type="submit">Build Example Template</button>
        </form>

        <p id="admin-trans-template-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Click Build Example Template to load the example.</p>
        <p id="admin-trans-template-summary" style="color:#355978; min-height:18px;"></p>
        <p><a id="admin-trans-template-download" href="#" style="display:none; font-weight:700;">Download CSV Output</a></p>
        <textarea id="admin-trans-template-preview" rows="8" readonly style="width:100%;"></textarea>
      </section>

      <section class="panel tool-panel" data-panel="jabbernotify">
        <h3>Send Jabber Training Notification</h3>
        <p>Search for an employee by last name, then send them the Cisco Jabber ready email (with their telephone number and training link). Use this to test or resend the notification.</p>
        <form id="jabbernotify-form">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>
          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>
          Last Name:<br>
          <input id="jabbernotify-last-name" placeholder="Smith" required style="width:min(280px,100%);"><br><br>
          First Name (optional):<br>
          <input id="jabbernotify-first-name" placeholder="John" style="width:min(280px,100%);"><br><br>
          <button type="submit">Search</button>
        </form>
        <p id="jabbernotify-search-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
        <div id="jabbernotify-results" style="overflow-x:auto;"></div>
        <p id="jabbernotify-send-status" style="margin-top:14px; font-weight:700; min-height:18px;"></p>
      </section>

      <section class="panel tool-panel" data-panel="bulkperson">
        <h3>Bulk Person Lookup (CSV Upload)</h3>
        <p>Upload CSV with columns like <strong>last_name, first_name</strong> (or first column as last name).</p>
        <p><a href="/download/bulk-person-template" style="font-weight:700;">Download Bulk Person Template</a></p>
        <form id="admin-bulk-person-form" enctype="multipart/form-data">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          CSV File:<br>
          <input type="file" name="csv_file" accept=".csv" required><br><br>

          <button type="submit">Run Bulk Person Lookup</button>
        </form>
        <p id="admin-bulk-person-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Upload a CSV to run bulk lookup.</p>
        <p id="admin-bulk-person-summary" style="color:#355978; min-height:18px;"></p>
        <p><a id="admin-bulk-person-download" href="#" style="display:none; font-weight:700;">Download CSV Output</a></p>
        <textarea id="admin-bulk-person-preview" rows="10" readonly style="width:100%;"></textarea>
      </section>

      <section class="panel tool-panel" data-panel="bulkextension">
        <h3>Bulk Extension Reverse Lookup (CSV Upload)</h3>
        <p>Upload CSV with a column like <strong>pattern</strong> or <strong>extension</strong> (or first column as pattern).</p>
        <p><a href="/download/bulk-extension-template" style="font-weight:700;">Download Bulk Extension Template</a></p>
        <form id="admin-bulk-extension-form" enctype="multipart/form-data">
          <div class="compact-inline-row">
            <span>Cisco Callmanager Username:</span>
            <input name="cucm_user" value="__AUTH_USER__" required>
          </div><br>

          <div class="compact-inline-row">
            <span>Cisco Callmanager Password:</span>
            <input type="password" name="cucm_pass" required>
          </div><br>

          CSV File:<br>
          <input type="file" name="csv_file" accept=".csv" required><br><br>

          <button type="submit">Run Bulk Extension Lookup</button>
        </form>
        <p id="admin-bulk-extension-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Upload a CSV to run bulk lookup.</p>
        <p id="admin-bulk-extension-summary" style="color:#355978; min-height:18px;"></p>
        <p><a id="admin-bulk-extension-download" href="#" style="display:none; font-weight:700;">Download CSV Output</a></p>
        <textarea id="admin-bulk-extension-preview" rows="10" readonly style="width:100%;"></textarea>
      </section>

      <script>
        (function () {
          // ── Jabber Notify panel ──────────────────────────────────────────────
          const jabberNotifyForm = document.getElementById("jabbernotify-form");
          const jabberNotifyStatus = document.getElementById("jabbernotify-search-status");
          const jabberNotifyResults = document.getElementById("jabbernotify-results");
          const jabberNotifySendStatus = document.getElementById("jabbernotify-send-status");

          if (jabberNotifyForm && jabberNotifyStatus && jabberNotifyResults) {
            jabberNotifyForm.addEventListener("submit", async function (event) {
              event.preventDefault();
              jabberNotifyStatus.textContent = "Searching...";
              jabberNotifyResults.innerHTML = "";
              if (jabberNotifySendStatus) jabberNotifySendStatus.textContent = "";

              const userField = jabberNotifyForm.querySelector('input[name="cucm_user"]');
              const passField = jabberNotifyForm.querySelector('input[name="cucm_pass"]');
              const lastNameEl = document.getElementById("jabbernotify-last-name");
              const firstNameEl = document.getElementById("jabbernotify-first-name");

              const lastName = ((lastNameEl && lastNameEl.value) || "").trim();
              const firstName = ((firstNameEl && firstNameEl.value) || "").trim();
              const cucmUser = ((userField && userField.value) || "").trim();
              const cucmPass = (passField && passField.value) || "";

              if (!lastName) {
                jabberNotifyStatus.textContent = "Last Name is required.";
                return;
              }
              if (!cucmUser || !cucmPass) {
                jabberNotifyStatus.textContent = "Enter CUCM credentials first.";
                return;
              }

              try {
                const fd = new FormData();
                fd.append("cucm_user", cucmUser);
                fd.append("cucm_pass", cucmPass);
                fd.append("last_name", lastName);
                fd.append("first_name", firstName);

                const resp = await fetch("/lookup/person", {
                  method: "POST",
                  body: fd,
                  credentials: "same-origin",
                  headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                });

                const payload = await resp.json();
                if (!resp.ok || !payload.ok) throw new Error((payload && payload.detail) || "Search failed.");

                const results = payload.results || [];
                if (!results.length) {
                  jabberNotifyStatus.textContent = "No users found.";
                  return;
                }

                jabberNotifyStatus.textContent = "Found " + results.length + " user(s). Click Send Notification to email a user.";

                let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
                html += '<thead><tr style="background:#005eb8; color:#fff;">';
                html += '<th style="padding:8px 10px; text-align:left;">Name</th>';
                html += '<th style="padding:8px 10px; text-align:left;">User ID</th>';
                html += '<th style="padding:8px 10px; text-align:left;">Telephone</th>';
                html += '<th style="padding:8px 10px; text-align:left;">Email</th>';
                html += '<th style="padding:8px 10px; text-align:left;">Action</th>';
                html += '</tr></thead><tbody>';

                results.forEach(function (r, i) {
                  const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                  const uid = r.userid || "";
                  const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || uid;
                  const telephone = r.telephone || "\u2014";
                  const email = r.email || "\u2014";
                  html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                  html += '<td style="padding:7px 10px;">' + name + '</td>';
                  html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                  html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                  html += '<td style="padding:7px 10px;">' + email + '</td>';
                  html += '<td style="padding:7px 10px;"><button type="button" data-notify-uid="' + uid + '" data-notify-tel="' + (r.telephone || "") + '" style="background:#237741;color:#fff;border:none;border-radius:6px;padding:6px 12px;font-weight:700;cursor:pointer;">Send Notification</button></td>';
                  html += '</tr>';
                });
                html += '</tbody></table>';
                jabberNotifyResults.innerHTML = html;

                jabberNotifyResults.querySelectorAll('button[data-notify-uid]').forEach(function (btn) {
                  btn.addEventListener("click", async function () {
                    const uid = btn.getAttribute("data-notify-uid") || "";
                    const tel = btn.getAttribute("data-notify-tel") || "";
                    if (jabberNotifySendStatus) jabberNotifySendStatus.textContent = "Sending...";
                    btn.disabled = true;

                    try {
                      const sf = new FormData();
                      sf.append("cucm_user", cucmUser);
                      sf.append("cucm_pass", cucmPass);
                      sf.append("target_user", uid);
                      sf.append("telephone", tel);

                      const sr = await fetch("/send/jabber-ready-email", {
                        method: "POST",
                        body: sf,
                        credentials: "same-origin",
                        headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                      });
                      const sp = await sr.json();
                      if (!sr.ok || !sp.ok) throw new Error((sp && sp.detail) || "Send failed.");
                      if (jabberNotifySendStatus) jabberNotifySendStatus.textContent = "Sent: " + (sp.detail || "Email sent successfully.");
                    } catch (err) {
                      if (jabberNotifySendStatus) jabberNotifySendStatus.textContent = "Failed: " + ((err && err.message) || "Unknown error.");
                      btn.disabled = false;
                    }
                  });
                });
              } catch (err) {
                jabberNotifyStatus.textContent = "Search error: " + ((err && err.message) || "Unknown.");
              }
            });
          }
          // ── End Jabber Notify panel ──────────────────────────────────────────

          const navButtons = Array.from(document.querySelectorAll(".portal-nav-btn"));
          const panels = Array.from(document.querySelectorAll(".tool-panel"));

          function showPanel(panelKey) {
            panels.forEach((panel) => {
              panel.classList.toggle("active", panel.dataset.panel === panelKey);
            });
            navButtons.forEach((btn) => {
              btn.classList.toggle("active", btn.dataset.panel === panelKey);
            });
          }

          navButtons.forEach((btn) => {
            btn.addEventListener("click", () => {
              showPanel(btn.dataset.panel);
            });
          });
        })();
      </script>

      <script>
        (function () {
          const form = document.getElementById("admin-person-lookup-form");
          const statusEl = document.getElementById("admin-person-lookup-status");
          const resultsEl = document.getElementById("admin-person-lookup-results");
          const strikeTargetInput = document.getElementById("admin-strike-target-user");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Searching...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              const response = await fetch("/lookup/person", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                const msg = (payload.error && payload.error.message) || "Search failed.";
                throw new Error(msg);
              }

              const results = payload.results || [];
              if (!results.length) {
                statusEl.textContent = "No users found matching that name.";
                return;
              }

              statusEl.textContent = `Found ${results.length} user(s).`;

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Extension</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Email</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Devices</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Actions</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                const ext = r.primary_extension || "\u2014";
                const email = r.email || "\u2014";
                const telephone = r.telephone || "\u2014";
                const uid = r.userid || "";
                const devList = (r.devices || []).map(function (d) {
                  const exts = (d.extensions || []).join(", ") || "\u2014";
                  return "<strong>" + d.name + "</strong> <span style='color:#555;font-size:12px;'>[" + d.type + "] " + exts + "</span>";
                }).join("<br>") || "\u2014";

                const btnStyle = "display:inline-block;margin:2px 3px 2px 0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;color:#fff;";
                const strikeBtn = `<button type="button" style="${btnStyle}background:#237741;" data-strike-user="${uid}">Strike Mode - Add in Both Jabber iPhone and Android</button>`;
                const tctBtn = `<button type="button" style="${btnStyle}background:#0e7490;" data-tct-user="${uid}">Add Jabber iPhone</button>`;
                const botBtn = `<button type="button" style="${btnStyle}background:#7c3aed;" data-bot-user="${uid}">Add Jabber Android</button>`;
                const notifyBtn = `<button type="button" style="${btnStyle}background:#1f7a3d;" data-notify-user="${uid}" data-notify-tel="${(r.telephone || "")}">Send Notification</button>`;
                const offboardBtn = `<button type="button" style="${btnStyle}background:#b00020;" data-offboard-user="${uid}">Separate Employee-Delete Jabber/VM</button>`;
                const actionBtn = strikeBtn + tctBtn + botBtn + notifyBtn + offboardBtn;

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px; font-weight:700; color:#002f6c;">' + ext + '</td>';
                html += '<td style="padding:7px 10px;">' + email + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px; line-height:1.6;">' + devList + '</td>';
                html += '<td style="padding:7px 10px; white-space:nowrap;">' + actionBtn + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;

              resultsEl.querySelectorAll("button[data-strike-user]").forEach(function (btn) {
                btn.addEventListener("click", function () {
                  const uid = btn.getAttribute("data-strike-user") || "";
                  if (strikeTargetInput) {
                    strikeTargetInput.value = uid;
                    strikeTargetInput.focus();
                  }
                  statusEl.textContent = `Loaded ${uid} into Strike Mode - Add in Both Jabber iPhone and Android.`;
                });
              });

              function submitAdminAction(endpoint, uid) {
                const userField = form.querySelector('input[name="cucm_user"]');
                const passField = form.querySelector('input[name="cucm_pass"]');
                const cucmUser = ((userField && userField.value) || "").trim();
                const cucmPass = (passField && passField.value) || "";

                if (!cucmUser || !cucmPass) {
                  statusEl.textContent = "Enter CUCM username/password in Employee Lookup by Name before running device actions.";
                  return;
                }

                const actionForm = document.createElement("form");
                actionForm.method = "post";
                actionForm.action = endpoint;

                const fields = {
                  cucm_user: cucmUser,
                  cucm_pass: cucmPass,
                  target_user: uid,
                  back_url: "/menu-admin",
                };

                Object.entries(fields).forEach(([name, value]) => {
                  const input = document.createElement("input");
                  input.type = "hidden";
                  input.name = name;
                  input.value = value;
                  actionForm.appendChild(input);
                });

                document.body.appendChild(actionForm);
                actionForm.submit();
              }

              resultsEl.querySelectorAll("button[data-tct-user]").forEach(function (btn) {
                btn.addEventListener("click", function () {
                  const uid = btn.getAttribute("data-tct-user") || "";
                  submitAdminAction("/add/secondary-tct-device", uid);
                });
              });

              resultsEl.querySelectorAll("button[data-bot-user]").forEach(function (btn) {
                btn.addEventListener("click", function () {
                  const uid = btn.getAttribute("data-bot-user") || "";
                  submitAdminAction("/add/secondary-bot-device", uid);
                });
              });

              resultsEl.querySelectorAll("button[data-offboard-user]").forEach(function (btn) {
                btn.addEventListener("click", function () {
                  const uid = btn.getAttribute("data-offboard-user") || "";
                  const qs = new URLSearchParams({ panel: "offboard", target_user: uid });
                  window.location.href = "/menu?" + qs.toString();
                });
              });

              resultsEl.querySelectorAll("button[data-notify-user]").forEach(function (btn) {
                btn.addEventListener("click", async function () {
                  const uid = btn.getAttribute("data-notify-user") || "";
                  const tel = btn.getAttribute("data-notify-tel") || "";
                  const userField = form.querySelector('input[name="cucm_user"]');
                  const passField = form.querySelector('input[name="cucm_pass"]');
                  const cucmUser = ((userField && userField.value) || "").trim();
                  const cucmPass = (passField && passField.value) || "";

                  if (!cucmUser || !cucmPass) {
                    statusEl.textContent = "Enter CUCM username/password before sending notification.";
                    return;
                  }

                  btn.disabled = true;
                  statusEl.textContent = `Sending Jabber notification for ${uid}...`;
                  try {
                    const sf = new FormData();
                    sf.append("cucm_user", cucmUser);
                    sf.append("cucm_pass", cucmPass);
                    sf.append("target_user", uid);
                    sf.append("telephone", tel);

                    const sr = await fetch("/send/jabber-ready-email", {
                      method: "POST",
                      body: sf,
                      credentials: "same-origin",
                      headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                    });
                    const sp = await sr.json();
                    if (!sr.ok || !sp.ok) {
                      throw new Error((sp && sp.detail) || "Send failed.");
                    }
                    statusEl.textContent = "Notification sent: " + (sp.detail || "Email sent successfully.");
                  } catch (err) {
                    statusEl.textContent = "Send failed: " + ((err && err.message) || "Unknown error.");
                    btn.disabled = false;
                  }
                });
              });
            } catch (err) {
              statusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();
      </script>

      <script>
        (function () {
          const form = document.getElementById("admin-mobile-delete-lookup-form");
          const statusEl = document.getElementById("admin-mobile-delete-status");
          const resultsEl = document.getElementById("admin-mobile-delete-results");

          if (!form || !statusEl || !resultsEl) return;

          function submitDeleteAction(uid, mode) {
            const userField = form.querySelector('input[name="cucm_user"]');
            const passField = form.querySelector('input[name="cucm_pass"]');
            const cucmUser = ((userField && userField.value) || "").trim();
            const cucmPass = (passField && passField.value) || "";

            if (!cucmUser || !cucmPass) {
              statusEl.textContent = "Enter CUCM username/password before running mobile device delete.";
              return;
            }

            const removeTct = mode === "tct" || mode === "both";
            const removeBot = mode === "bot" || mode === "both";
            const label = mode === "tct" ? "TCT only" : (mode === "bot" ? "BOT only" : "TCT and BOT");

            const confirmed = confirm(
              `Delete mobile Jabber devices for ${uid}?\\n\\nSelection: ${label}\\n\\nThis action will not delete CSF or voicemail.`
            );
            if (!confirmed) {
              return;
            }

            const actionForm = document.createElement("form");
            actionForm.method = "post";
            actionForm.action = "/delete/secondary-mobile-devices";

            const fields = {
              cucm_user: cucmUser,
              cucm_pass: cucmPass,
              target_user: uid,
              remove_tct: removeTct ? "1" : "0",
              remove_bot: removeBot ? "1" : "0",
            };

            Object.entries(fields).forEach(([name, value]) => {
              const input = document.createElement("input");
              input.type = "hidden";
              input.name = name;
              input.value = value;
              actionForm.appendChild(input);
            });

            document.body.appendChild(actionForm);
            actionForm.submit();
          }

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Searching...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              const response = await fetch("/lookup/person", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                const msg = (payload.error && payload.error.message) || "Search failed.";
                throw new Error(msg);
              }

              const results = payload.results || [];
              if (!results.length) {
                statusEl.textContent = "No users found matching that name.";
                return;
              }

              statusEl.textContent = `Found ${results.length} user(s). Choose delete action.`;

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Email</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Devices</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Delete Actions</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                const email = r.email || "\u2014";
                const telephone = r.telephone || "\u2014";
                const uid = r.userid || "";
                const devList = (r.devices || []).map(function (d) {
                  const exts = (d.extensions || []).join(", ") || "\u2014";
                  return "<strong>" + d.name + "</strong> <span style='color:#555;font-size:12px;'>[" + d.type + "] " + exts + "</span>";
                }).join("<br>") || "\u2014";

                const btnStyle = "display:inline-block;margin:2px 3px 2px 0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;color:#fff;";
                const tctBtn = `<button type="button" style="${btnStyle}background:#0e7490;" data-delete-mode="tct" data-delete-user="${uid}">Delete iPhone (TCT)</button>`;
                const botBtn = `<button type="button" style="${btnStyle}background:#7c3aed;" data-delete-mode="bot" data-delete-user="${uid}">Delete Android (BOT)</button>`;
                const bothBtn = `<button type="button" style="${btnStyle}background:#b00020;" data-delete-mode="both" data-delete-user="${uid}">Delete Both</button>`;

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px;">' + email + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px; line-height:1.6;">' + devList + '</td>';
                html += '<td style="padding:7px 10px; white-space:nowrap;">' + tctBtn + botBtn + bothBtn + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;

              resultsEl.querySelectorAll("button[data-delete-mode]").forEach(function (btn) {
                btn.addEventListener("click", function () {
                  const uid = btn.getAttribute("data-delete-user") || "";
                  const mode = btn.getAttribute("data-delete-mode") || "";
                  submitDeleteAction(uid, mode);
                });
              });

            } catch (err) {
              statusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();
      </script>

      <script>
        (function () {
          const form = document.getElementById("admin-trans-pattern-form");
          const statusEl = document.getElementById("admin-trans-pattern-status");
          const resultsEl = document.getElementById("admin-trans-pattern-results");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Searching translation patterns...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              const response = await fetch("/lookup/translation-pattern", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                const msg = (payload.error && payload.error.message) || "Lookup failed.";
                throw new Error(msg);
              }

              const results = payload.results || [];
              if (!results.length) {
                statusEl.textContent = "No translation patterns found.";
                return;
              }

              statusEl.textContent = `Found ${results.length} translation pattern(s).`;

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Pattern</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Description</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Called Party Transform Mask</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (item, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace; color:#002f6c; font-weight:700;">' + (item.pattern || "\u2014") + '</td>';
                html += '<td style="padding:7px 10px;">' + (item.description || "\u2014") + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (item.called_party_transform_mask || "\u2014") + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();
      </script>

      <script>
        (function () {
          const form = document.getElementById("admin-trans-template-form");
          const statusEl = document.getElementById("admin-trans-template-status");
          const summaryEl = document.getElementById("admin-trans-template-summary");
          const previewEl = document.getElementById("admin-trans-template-preview");
          const downloadEl = document.getElementById("admin-trans-template-download");

          if (!form || !statusEl || !summaryEl || !previewEl || !downloadEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Building translation pattern template...";
            summaryEl.textContent = "";
            previewEl.value = "";
            downloadEl.style.display = "none";
            downloadEl.removeAttribute("href");

            try {
              const formData = new FormData(form);
              const response = await fetch("/translation-pattern/template/from-example", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                const msg = (payload.error && payload.error.message) || "Template build failed.";
                throw new Error(msg);
              }

              statusEl.textContent = `Loaded example pattern ${payload.example.pattern || ""}.`;
              summaryEl.textContent = `Route Partition: ${payload.example.route_partition || ""} | Called Party Transform Mask: ${payload.example.called_party_transform_mask || ""}`;
              previewEl.value = payload.output_text || "";
              if (payload.download_url) {
                downloadEl.href = payload.download_url;
                downloadEl.style.display = "inline";
              }
            } catch (err) {
              statusEl.textContent = "Template build failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();
      </script>

      <script>
        (function () {
          function renderSummary(summary) {
            if (!summary) return "";
            return `Input rows: ${summary.input_rows || 0} | Matched: ${summary.matched_inputs || 0} | No results: ${summary.no_result_inputs || 0} | Errors: ${summary.error_inputs || 0} | Output rows: ${summary.output_rows || 0}`;
          }

          async function runBulkLookup(config) {
            const form = document.getElementById(config.formId);
            const statusEl = document.getElementById(config.statusId);
            const summaryEl = document.getElementById(config.summaryId);
            const previewEl = document.getElementById(config.previewId);
            const downloadEl = document.getElementById(config.downloadId);
            if (!form || !statusEl || !summaryEl || !previewEl || !downloadEl) {
              return;
            }

            form.addEventListener("submit", async function (event) {
              event.preventDefault();
              statusEl.textContent = config.runningText;
              summaryEl.textContent = "";
              previewEl.value = "";
              downloadEl.style.display = "none";
              downloadEl.removeAttribute("href");

              try {
                const formData = new FormData(form);
                const response = await fetch(config.endpoint, {
                  method: "POST",
                  body: formData,
                  credentials: "same-origin",
                });

                const payload = await response.json();
                if (!response.ok || !payload.ok) {
                  const msg = (payload.error && payload.error.message) || "Bulk lookup failed.";
                  throw new Error(msg);
                }

                statusEl.textContent = `Completed: ${payload.filename || config.defaultFilename}`;
                summaryEl.textContent = renderSummary(payload.summary);
                previewEl.value = payload.output_text || "";
                if (payload.download_url) {
                  downloadEl.href = payload.download_url;
                  downloadEl.style.display = "inline";
                }
              } catch (err) {
                statusEl.textContent = config.failedText;
                summaryEl.textContent = "";
                previewEl.value = (err && err.message) ? err.message : "Unknown error.";
              }
            });
          }

          runBulkLookup({
            formId: "admin-bulk-person-form",
            statusId: "admin-bulk-person-status",
            summaryId: "admin-bulk-person-summary",
            previewId: "admin-bulk-person-preview",
            downloadId: "admin-bulk-person-download",
            endpoint: "/bulk/lookup/person",
            runningText: "Running bulk person lookup...",
            failedText: "Bulk person lookup failed.",
            defaultFilename: "bulk_person_lookup.csv",
          });

          runBulkLookup({
            formId: "admin-bulk-extension-form",
            statusId: "admin-bulk-extension-status",
            summaryId: "admin-bulk-extension-summary",
            previewId: "admin-bulk-extension-preview",
            downloadId: "admin-bulk-extension-download",
            endpoint: "/bulk/lookup/extension",
            runningText: "Running bulk extension lookup...",
            failedText: "Bulk extension lookup failed.",
            defaultFilename: "bulk_extension_lookup.csv",
          });
        })();
      </script>
        </section>
      </div>
    </main>
  </body>
</html>
""".replace("__AUTH_USER__", auth_user).replace("__ENV_TEXT__", escape(env_text)).replace("__ENV_CLASS__", env_css_class)

  return HTMLResponse(
    content=html,
    headers={
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "Pragma": "no-cache",
      "Expires": "0",
    },
  )


@app.get("/download/add-directorynumbers-template")
def download_add_directorynumbers_template():
  template_csv = "pattern\n5551001\n5551002\n"
  return Response(
    template_csv.encode("utf-8"),
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="add_directory_numbers_template.csv"'}
  )


@app.get("/download/bulk-person-template")
def download_bulk_person_template():
  template_csv = "last_name,first_name\nBeavers,Sean\nSmith,Jane\n"
  return Response(
    template_csv.encode("utf-8"),
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="bulk_person_lookup_template.csv"'}
  )


@app.get("/download/bulk-extension-template")
def download_bulk_extension_template():
  template_csv = "pattern\n5551001\n5551002\n"
  return Response(
    template_csv.encode("utf-8"),
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="bulk_extension_lookup_template.csv"'}
  )


@app.get("/healthz")
def healthz():
  now_epoch = time.time()
  _prune_auth_sessions_locked(now_epoch)
  with AUDIT_LOG_LOCK:
    _ensure_audit_log()
    _prune_audit_log_locked()

  return JSONResponse(
    {
      "status": "ok",
      "service": "cucm-web",
      "timestamp": datetime.datetime.now().strftime(AUDIT_TIMESTAMP_FORMAT),
      "uptime_seconds": int(now_epoch - APP_START_EPOCH),
      "active_sessions": len(AUTH_SESSIONS),
      "job_output_cache_entries": len(JOB_OUTPUTS),
      "audit_log_exists": os.path.exists(AUDIT_LOG_PATH),
      "audit_retention_days": AUDIT_RETENTION_DAYS,
    }
  )


@app.get("/download/job-output/{job_id}")
def download_job_output(job_id: str):
  job_output = JOB_OUTPUTS.get(job_id)
  if not job_output:
    return Response("Job output not found.", media_type="text/plain", status_code=404)

  return Response(
    job_output["data"],
    media_type="text/csv",
    headers={"Content-Disposition": f'attachment; filename="{job_output["filename"]}"'}
  )


@app.get("/download/audit-trail")
def download_audit_trail():
  with AUDIT_LOG_LOCK:
    _ensure_audit_log()
    _prune_audit_log_locked()
    with open(AUDIT_LOG_PATH, "rb") as handle:
      data = handle.read()

  return Response(
    data,
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="audit_trail.csv"'}
  )


@app.get("/audit-trail/stats")
def audit_trail_stats():
  with AUDIT_LOG_LOCK:
    _ensure_audit_log()
    _prune_audit_log_locked()
    with open(AUDIT_LOG_PATH, "r", newline="", encoding="utf-8") as handle:
      reader = csv.DictReader(handle)
      record_count = sum(1 for _ in reader)

  return JSONResponse({
    "audit_log_path": AUDIT_LOG_PATH,
    "retention_days": AUDIT_RETENTION_DAYS,
    "record_count": record_count,
  })


@app.post("/add/directorynumbers")
async def add_directorynumbers(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    csv_file: UploadFile = File(...)
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    csv_bytes = await csv_file.read()
    log_csv, filename = add_directory_numbers_from_csv(
        cucm_host, cucm_user, cucm_pass, csv_bytes, {}
    )
    csv_name = csv_file.filename or "uploaded.csv"
    _append_audit_event(
      action="add_directory_numbers",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=csv_name,
      output_filename=filename,
      inline_mode=False,
    )
    return _render_job_result("Add Directory Numbers", log_csv, filename, back_url="/menu-admin")


@app.post("/export/directorynumbers")
def export_directorynumbers(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    dn_contains: str = Form(...),
    route_partition: str = Form("")
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    data, filename = export_directory_numbers(
        cucm_host, cucm_user, cucm_pass, dn_contains, route_partition
    )
    target = f"pattern={dn_contains};partition={route_partition or '*'}"
    _append_audit_event(
      action="export_directory_numbers",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=target,
      output_filename=filename,
      inline_mode=False,
    )
    return _render_job_result("Export Directory Numbers", data, filename, back_url="/menu-admin")


@app.post("/export/endusers")
def export_endusers(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    lastname: str = Form(...)
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    data, filename = export_endusers_all_fields(
        cucm_host, cucm_user, cucm_pass, lastname
    )
    _append_audit_event(
      action="export_end_users",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=lastname,
      output_filename=filename,
      inline_mode=False,
    )
    return _render_job_result("Export End Users", data, filename, back_url="/menu-admin")


@app.post("/build/user-csf-phone")
async def build_user_csf_phone(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    dn_type: str = Form("general"),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    clean_target_user = (target_user or "").strip()
    data, filename = build_user_csf_phone_from_template(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=clean_target_user,
        dn_type=dn_type,
        ad_username=cucm_user,
        ad_password=cucm_pass,
    )
    added_dn = _extract_added_dn_from_build_output(data)
    added_count = 1 if added_dn else 0
    audit_target = f"account={clean_target_user};dn_added={added_dn or 'none'};added_count={added_count}"
    _append_audit_event(
      action="build_user_csf_phone",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=audit_target,
      account=clean_target_user,
      extension_added=added_dn,
      extension_deleted="",
      output_filename=filename,
      inline_mode=inline,
    )

    notify_status, notify_details = _send_csf_jabber_ready_email_if_created(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=clean_target_user,
      added_dn=added_dn,
      new_build=True,
    )
    data = _append_result_row(data, "Send Jabber Ready Email", notify_status, notify_details)

    if inline:
        job_output = _prepare_job_output(data, filename)
        return JSONResponse({
            "job_id": job_output["job_id"],
            "filename": job_output["filename"],
            "output_text": job_output["output_text"],
            "download_url": f"/download/job-output/{job_output['job_id']}",
        })

    return _render_job_result("Build User CSF Phone", data, filename)


@app.post("/build/teams-telephony-user")
async def build_teams_telephony_user(
  request: Request,
  cucm_host: str = Form(""),
  cucm_user: str = Form(""),
  cucm_pass: str = Form(""),
  target_user: str = Form(...),
  inline: bool = Query(False),
):
  cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
  _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
  clean_target_user = (target_user or "").strip()
  data, filename = create_teams_telephony_user(
    cucm_host=cucm_host,
    cucm_user=cucm_user,
    cucm_pass=cucm_pass,
    target_user=clean_target_user,
    ad_username=cucm_user,
    ad_password=cucm_pass,
  )
  added_dn = _extract_added_dn_from_build_output(data)
  added_count = 1 if added_dn else 0
  audit_target = f"account={clean_target_user};dn_added={added_dn or 'none'};added_count={added_count}"
  _append_audit_event(
    action="build_teams_telephony_user",
    cucm_host=cucm_host,
    operator=cucm_user,
    target=audit_target,
    account=clean_target_user,
    extension_added=added_dn,
    extension_deleted="",
    output_filename=filename,
    inline_mode=inline,
  )

  if inline:
    job_output = _prepare_job_output(data, filename)
    return JSONResponse({
      "job_id": job_output["job_id"],
      "filename": job_output["filename"],
      "output_text": job_output["output_text"],
      "download_url": f"/download/job-output/{job_output['job_id']}",
    })

  return _render_job_result("Create Teams Telephony User", data, filename)


@app.post("/teams-telephony/remove/lookup")
def teams_telephony_remove_lookup(
  request: Request,
  cucm_host: str = Form(""),
  cucm_user: str = Form(""),
  cucm_pass: str = Form(""),
  target_user: str = Form(...),
):
  cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
  _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
  clean_target_user = (target_user or "").strip()
  if not clean_target_user:
    _append_audit_event(
      action="lookup_remove_teams_mapping",
      cucm_host=cucm_host,
      operator=cucm_user,
      target="account=(blank)",
      account="",
      extension_added="",
      extension_deleted="",
      output_filename="inline_json_error",
      inline_mode=True,
    )
    return JSONResponse({
      "ok": False,
      "error": {
        "message": "Target user is required.",
      },
    })

  try:
    result = lookup_teams_telephony_removal_candidate(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=clean_target_user,
    )
    _append_audit_event(
      action="lookup_remove_teams_mapping",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=f"account={clean_target_user}",
      account=clean_target_user,
      extension_added="",
      extension_deleted="",
      output_filename="inline_json_ok",
      inline_mode=True,
    )
    return JSONResponse({"ok": True, **result})
  except Exception as exc:
    _append_audit_event(
      action="lookup_remove_teams_mapping",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=f"account={clean_target_user}",
      account=clean_target_user,
      extension_added="",
      extension_deleted="",
      output_filename="inline_json_error",
      inline_mode=True,
    )
    return JSONResponse({
      "ok": False,
      "error": {
        "message": str(exc) or "Lookup failed.",
      },
    })


@app.post("/teams-telephony/remove")
async def teams_telephony_remove_execute(
  request: Request,
  cucm_host: str = Form(""),
  cucm_user: str = Form(""),
  cucm_pass: str = Form(""),
  target_user: str = Form(...),
  inline: bool = Query(False),
):
  cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
  _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
  clean_target_user = (target_user or "").strip()
  data, filename = remove_teams_telephony_user(
    cucm_host=cucm_host,
    cucm_user=cucm_user,
    cucm_pass=cucm_pass,
    target_user=clean_target_user,
    ad_username=cucm_user,
    ad_password=cucm_pass,
  )

  _append_audit_event(
    action="remove_teams_telephony_user",
    cucm_host=cucm_host,
    operator=cucm_user,
    target=f"account={clean_target_user}",
    account=clean_target_user,
    extension_added="",
    extension_deleted="",
    output_filename=filename,
    inline_mode=inline,
  )

  if inline:
    job_output = _prepare_job_output(data, filename)
    return JSONResponse({
      "job_id": job_output["job_id"],
      "filename": job_output["filename"],
      "output_text": job_output["output_text"],
      "download_url": f"/download/job-output/{job_output['job_id']}",
    })

  return _render_job_result("Remove Teams Telephony User", data, filename)


@app.post("/rebuild/user-csf-phone")
async def rebuild_user_csf_phone(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    inline: bool = Query(False),
  ):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    clean_target_user = (target_user or "").strip()

    rebuild_dn = _find_latest_rebuild_dn_from_audit(clean_target_user)
    if not rebuild_dn:
      data = b"Step,Status,Details\nAudit Lookup,Failed,No offboard extension found for this user in audit trail\n"
      filename = f"rebuild_user_csf_phone_{clean_target_user or 'unknown'}_no_audit_match.csv"
    else:
      data, filename = build_user_csf_phone_from_template(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=clean_target_user,
        dn_type="general",
        ad_username=cucm_user,
        ad_password=cucm_pass,
        preferred_dn=rebuild_dn,
      )

    added_dn = _extract_added_dn_from_build_output(data)
    audit_target = (
      f"account={clean_target_user};dn_from_audit={rebuild_dn or 'none'};dn_added={added_dn or 'none'}"
    )
    _append_audit_event(
      action="rebuild_user_csf_phone_from_audit",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=audit_target,
      account=clean_target_user,
      extension_added=added_dn,
      extension_deleted=rebuild_dn,
      output_filename=filename,
      inline_mode=inline,
    )

    notify_status, notify_details = _send_csf_jabber_ready_email_if_created(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=clean_target_user,
      added_dn=added_dn,
    )
    data = _append_result_row(data, "Send Jabber Ready Email", notify_status, notify_details)

    if inline:
      job_output = _prepare_job_output(data, filename)
      return JSONResponse({
        "job_id": job_output["job_id"],
        "filename": job_output["filename"],
        "output_text": job_output["output_text"],
        "download_url": f"/download/job-output/{job_output['job_id']}",
      })

    return _render_job_result("Re-Build Cisco Jabber CSF from Offboard Audit", data, filename)


@app.post("/check/user-devices")
def check_user_devices_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    clean_target = (target_user or "").strip()
    if not clean_target:
        raise RuntimeError("target_user is required.")
    result = check_user_devices(cucm_host, cucm_user, cucm_pass, clean_target)
    return JSONResponse({"ok": True, **result})


@app.post("/lookup/extension")
def lookup_extension_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    pattern: str = Form(...),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    clean_pattern = (pattern or "").strip()
    if not clean_pattern:
        raise RuntimeError("Extension pattern is required.")
    result = lookup_extension_owner(cucm_host, cucm_user, cucm_pass, clean_pattern)
    return JSONResponse({"ok": True, **result})


@app.post("/lookup/translation-pattern")
def lookup_translation_pattern_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    pattern_query: str = Form(...),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    clean_pattern = (pattern_query or "").strip()
    if not clean_pattern:
      raise RuntimeError("Pattern query is required.")

    results = lookup_translation_patterns(cucm_host, cucm_user, cucm_pass, clean_pattern)
    return JSONResponse({"ok": True, "query": clean_pattern, "results": results})


@app.post("/translation-pattern/template/from-example")
def translation_pattern_template_from_example_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    pattern_prefix: str = Form("3148984689"),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    clean_prefix = (pattern_prefix or "").strip() or "3148984689"

    data, filename, example = build_translation_pattern_template(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        pattern_prefix=clean_prefix,
    )

    _append_audit_event(
      action="translation_pattern_template_from_example",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=clean_prefix,
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
      job_output = _prepare_job_output(data, filename)
      return JSONResponse({
        "ok": True,
        "job_id": job_output["job_id"],
        "filename": job_output["filename"],
        "output_text": job_output["output_text"],
        "download_url": f"/download/job-output/{job_output['job_id']}",
        "example": example,
      })

    job_output = _prepare_job_output(data, filename)
    return JSONResponse({
      "ok": True,
      "job_id": job_output["job_id"],
      "filename": job_output["filename"],
      "output_text": job_output["output_text"],
      "download_url": f"/download/job-output/{job_output['job_id']}",
      "example": example,
    })


@app.post("/bulk/lookup/person")
async def bulk_lookup_person_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    csv_file: UploadFile = File(...),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    raw = await csv_file.read()
    text = raw.decode("utf-8-sig", errors="replace")
    inputs = _parse_bulk_person_inputs(text)
    if not inputs:
      raise RuntimeError("No usable rows found in CSV. Include a last name column or first column with last names.")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
      "input_last_name",
      "input_first_name",
      "status",
      "userid",
      "display_name",
      "email",
      "telephone",
      "primary_extension",
      "devices",
      "details",
    ])

    matched_inputs = 0
    no_result_inputs = 0
    error_inputs = 0
    result_rows = 0

    for last_name, first_name in inputs:
      try:
        results = search_persons_by_name(cucm_host, cucm_user, cucm_pass, last_name, first_name)
      except Exception as exc:
        error_inputs += 1
        writer.writerow([last_name, first_name, "ERROR", "", "", "", "", "", "", str(exc)])
        result_rows += 1
        continue

      if not results:
        no_result_inputs += 1
        writer.writerow([last_name, first_name, "NO_RESULTS", "", "", "", "", "", "", "No users matched"])
        result_rows += 1
        continue

      matched_inputs += 1
      for person in results:
        devices = person.get("devices") or []
        device_text = " | ".join(
          f"{d.get('name', '')}:{','.join(d.get('extensions') or []) or '-'}"
          for d in devices
        )
        writer.writerow([
          last_name,
          first_name,
          "FOUND",
          person.get("userid", ""),
          person.get("display_name", ""),
          person.get("email", ""),
          person.get("telephone", ""),
          person.get("primary_extension", ""),
          device_text,
          "",
        ])
        result_rows += 1

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bulk_person_lookup_{timestamp}.csv"
    job_output = _prepare_job_output(output.getvalue().encode("utf-8"), filename)

    _append_audit_event(
      action="bulk_lookup_person",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=f"rows={len(inputs)}",
      output_filename=filename,
      inline_mode=True,
    )

    return JSONResponse({
      "ok": True,
      "summary": {
        "input_rows": len(inputs),
        "matched_inputs": matched_inputs,
        "no_result_inputs": no_result_inputs,
        "error_inputs": error_inputs,
        "output_rows": result_rows,
      },
      "job_id": job_output["job_id"],
      "filename": job_output["filename"],
      "output_text": job_output["output_text"],
      "download_url": f"/download/job-output/{job_output['job_id']}",
    })


@app.post("/bulk/lookup/extension")
async def bulk_lookup_extension_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    csv_file: UploadFile = File(...),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    raw = await csv_file.read()
    text = raw.decode("utf-8-sig", errors="replace")
    patterns = _parse_bulk_extension_inputs(text)
    if not patterns:
      raise RuntimeError("No usable rows found in CSV. Include a pattern/extension column or first column with patterns.")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
      "input_pattern",
      "status",
      "matched_pattern",
      "partition",
      "device_name",
      "device_type",
      "owner_userid",
      "owner_display_name",
      "owner_email",
      "details",
    ])

    matched_inputs = 0
    no_result_inputs = 0
    error_inputs = 0
    result_rows = 0

    for pattern in patterns:
      try:
        result = lookup_extension_owner(cucm_host, cucm_user, cucm_pass, pattern)
        matches = result.get("matches") or []
      except Exception as exc:
        error_inputs += 1
        writer.writerow([pattern, "ERROR", "", "", "", "", "", "", "", str(exc)])
        result_rows += 1
        continue

      if not matches:
        no_result_inputs += 1
        writer.writerow([pattern, "NO_RESULTS", "", "", "", "", "", "", "", "No matches found"])
        result_rows += 1
        continue

      matched_inputs += 1
      for match in matches:
        user = match.get("user") or {}
        writer.writerow([
          pattern,
          "FOUND",
          match.get("pattern", ""),
          match.get("partition", ""),
          match.get("device_name", ""),
          match.get("device_type", ""),
          match.get("owner_userid", ""),
          user.get("display_name", ""),
          user.get("email", ""),
          "",
        ])
        result_rows += 1

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bulk_extension_lookup_{timestamp}.csv"
    job_output = _prepare_job_output(output.getvalue().encode("utf-8"), filename)

    _append_audit_event(
      action="bulk_lookup_extension",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=f"rows={len(patterns)}",
      output_filename=filename,
      inline_mode=True,
    )

    return JSONResponse({
      "ok": True,
      "summary": {
        "input_rows": len(patterns),
        "matched_inputs": matched_inputs,
        "no_result_inputs": no_result_inputs,
        "error_inputs": error_inputs,
        "output_rows": result_rows,
      },
      "job_id": job_output["job_id"],
      "filename": job_output["filename"],
      "output_text": job_output["output_text"],
      "download_url": f"/download/job-output/{job_output['job_id']}",
    })


@app.post("/send/jabber-ready-email")
def send_jabber_ready_email_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    telephone: str = Form(""),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    clean_target = (target_user or "").strip()
    phone = (telephone or "").strip()

    # If no phone provided by caller, look it up from CUCM
    if not phone:
        try:
            _, _ = _lookup_user_contact(cucm_host, cucm_user, cucm_pass, clean_target)
        except Exception:
            pass
        # Re-fetch with full details via person lookup
        results = search_persons_by_name(cucm_host, cucm_user, cucm_pass, "", "")
        for r in results:
            if (r.get("userid") or "").strip().lower() == clean_target.lower():
                phone = (r.get("telephone") or "").strip()
                break

    if not phone:
        # Fall back to mailid lookup to at least get recipient
        pass

    notify_status, notify_details = _send_csf_jabber_ready_email_if_created(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=clean_target,
        added_dn=phone,
    )

    if notify_status == "Success":
        return JSONResponse({"ok": True, "detail": notify_details})
    else:
        return JSONResponse({"ok": False, "detail": notify_details}, status_code=400)


@app.post("/send/mobile-jabber-email")
def send_mobile_jabber_email_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    telephone: str = Form(""),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    clean_target = (target_user or "").strip()
    phone = (telephone or "").strip()

    notify_status, notify_details = _send_mobile_jabber_ready_email(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=clean_target,
      phone_number=phone,
    )

    _append_audit_event(
      action="send_mobile_jabber_email",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=clean_target,
      notes=f"status={notify_status}; detail={notify_details}",
      inline_mode=True,
    )

    if notify_status == "Success":
        return JSONResponse({"ok": True, "detail": notify_details})
    else:
        return JSONResponse({"ok": False, "detail": notify_details}, status_code=400)


@app.post("/lookup/person")
def lookup_person_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    last_name: str = Form(...),
    first_name: str = Form(""),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    clean_last = (last_name or "").strip()
    clean_first = (first_name or "").strip()
    if not clean_last:
        raise RuntimeError("Last Name is required.")
    results = search_persons_by_name(cucm_host, cucm_user, cucm_pass, clean_last, clean_first)
    return JSONResponse({
        "ok": True,
        "count": len(results),
        "results": results,
        "query": {"last_name": clean_last, "first_name": clean_first},
    })


@app.post("/check/jabber-status")
def check_jabber_status_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
  embedded: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    result = lookup_user_jabber_status(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=target_user,
    )

    _append_audit_event(
      action="check_jabber_status",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=target_user,
      output_filename="inline_json",
      inline_mode=True,
    )

    is_ajax = (request.headers.get("x-requested-with", "").lower() == "xmlhttprequest")
    if is_ajax:
      return JSONResponse(result)

    html_result = f"""
<!doctype html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <title>Jabber Pre-Check Result</title>
    <style>
      body {{ font-family: Segoe UI, Arial, sans-serif; background: #f4f8fc; color: #10324f; margin: 24px; }}
      .card {{ max-width: 880px; background: #ffffff; border: 1px solid #d7e2ee; border-radius: 10px; padding: 18px; }}
      pre {{ background: #eef5fb; border: 1px solid #d7e2ee; border-radius: 8px; padding: 12px; white-space: pre-wrap; }}
      a {{ color: #005cb9; font-weight: 600; }}
    </style>
  </head>
  <body>
    <div class=\"card\">
      <h2>Jabber Pre-Check Result</h2>
      <pre>{escape(chr(10).join([
        f"User: {result.get('target_user', '')}",
        f"Jabber Built: {'YES' if result.get('jabber_built') else 'NO'}",
        f"Device Name: {result.get('device_name') or 'Not found'}",
        f"Jabber Extension: {result.get('extension') or 'Not found'}",
        f"Voicemail Extension: {result.get('voicemail_extension') or 'Not found'}",
        f"Environment: {result.get('environment', '')}",
        f"CUCM Host: {result.get('cucm_host', '')}",
        f"Unity Server: {result.get('unity_server', '')}",
        f"Unity Lookup Error: {result.get('unity_lookup_error', '')}" if result.get('unity_lookup_error') else "",
      ]))}</pre>
      <p><a href=\"/menu\">Back to Menu</a></p>
    </div>
  </body>
</html>
"""

    if embedded:
      return HTMLResponse(content=html_result)

    return HTMLResponse(content=html_result)


@app.post("/decommission/user-csf-voicemail")
def decommission_user_csf_voicemail_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    clean_target_user = (target_user or "").strip()
    data, filename = decommission_user_csf_voicemail(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=clean_target_user,
        ad_username=cucm_user,
        ad_password=cucm_pass,
    )
    deleted_dns = _extract_deleted_dns_from_offboard_output(data)
    deleted_dn_text = "|".join(deleted_dns) if deleted_dns else "none"
    audit_target = (
      f"account={clean_target_user};dn_deleted={deleted_dn_text};deleted_count={len(deleted_dns)}"
    )
    _append_audit_event(
      action="offboard_user_option_10",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=audit_target,
      account=clean_target_user,
      extension_added="",
      extension_deleted=deleted_dn_text if deleted_dn_text != "none" else "",
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
        job_output = _prepare_job_output(data, filename)
        return JSONResponse({
            "job_id": job_output["job_id"],
            "filename": job_output["filename"],
            "output_text": job_output["output_text"],
            "download_url": f"/download/job-output/{job_output['job_id']}",
        })

    return _render_job_result("Offboard User - Delete all Jabber and Voicemail Box (Option 10)", data, filename)


@app.post("/reset/unity-voicemail-pin")
def reset_unity_voicemail_pin_route(
    request: Request,
    unity_user: str = Form(""),
    unity_pass: str = Form(""),
    voicemail_user: str = Form(...),
    new_voicemail_pin: str = Form(...),
    confirm_voicemail_pin: str = Form(...),
    inline: bool = Query(False),
):
    unity_server = _get_unity_server_for_session(request)
    unity_user, unity_pass = _resolve_unity_credentials(request, unity_user, unity_pass)
    _update_cached_credentials(request, unity_user=unity_user)
    if new_voicemail_pin != confirm_voicemail_pin:
      data = b"Step,Status,Details\nValidation,Failed,Voicemail PIN values must match\n"
      filename = "reset_unity_voicemail_pin_validation_error.csv"
    else:
      data, filename = reset_unity_voicemail_pin(
        unity_server=unity_server,
        unity_user=unity_user,
        unity_pass=unity_pass,
        target_alias=voicemail_user,
        new_pin=new_voicemail_pin,
      )

    _append_audit_event(
      action="reset_unity_voicemail_pin_option_2",
      cucm_host=unity_server,
      operator=unity_user,
      target=voicemail_user,
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
      job_output = _prepare_job_output(data, filename)
      return JSONResponse({
        "job_id": job_output["job_id"],
        "filename": job_output["filename"],
        "output_text": job_output["output_text"],
        "download_url": f"/download/job-output/{job_output['job_id']}",
      })

    return _render_job_result("Reset Unity Voicemail PIN (Option 2)", data, filename)


@app.post("/update/ad-phone-fields")
def update_ad_phone_fields_route(
    request: Request,
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    phone_number: str = Form(""),
    inline: bool = Query(False),
):
    _update_cached_credentials(request, cucm_host="", cucm_user=cucm_user)
    data, filename = update_ad_phone_fields_only(
      target_user=target_user,
      phone_number=phone_number,
      ad_username=cucm_user,
      ad_password=cucm_pass,
    )
    _append_audit_event(
      action="update_ad_phone_only_option_11",
      cucm_host="",
      operator=cucm_user,
      target=target_user,
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
      job_output = _prepare_job_output(data, filename)
      return JSONResponse({
        "job_id": job_output["job_id"],
        "filename": job_output["filename"],
        "output_text": job_output["output_text"],
        "download_url": f"/download/job-output/{job_output['job_id']}",
      })

    return _render_job_result("Update Active Directory Telephone and ipPhone field only (Option 11)", data, filename)


@app.post("/called-name-change")
def called_name_change_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    unity_server = _get_unity_server_for_session(request)
    clean_target_user = (target_user or "").strip()

    data, filename = run_called_name_change(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      unity_server=unity_server,
      target_user=clean_target_user,
    )

    _append_audit_event(
      action="called_name_change",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=clean_target_user,
      account=clean_target_user,
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
      job_output = _prepare_job_output(data, filename)
      return JSONResponse({
        "job_id": job_output["job_id"],
        "filename": job_output["filename"],
        "output_text": job_output["output_text"],
        "download_url": f"/download/job-output/{job_output['job_id']}",
      })

    return _render_job_result("Employee Name Change-Update Jabber/VM", data, filename)


@app.post("/add/secondary-tct-device")
def add_secondary_tct_device_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    back_url: str = Form("/menu"),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    data, filename = add_secondary_tct_device(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )
    try:
      notify_status, notify_details = _send_mobile_jabber_ready_email_if_built(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
        csv_data=data,
        created_steps={"Add TCT Device"},
      )
    except Exception as exc:
      notify_status, notify_details = "Failed", f"Email notification failed: {exc}"
    data = _append_result_row(data, "Notify End User", notify_status, notify_details)
    _append_audit_event(
      action="add_secondary_tct_option_3",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=target_user,
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
        job_output = _prepare_job_output(data, filename)
        return JSONResponse({
            "job_id": job_output["job_id"],
            "filename": job_output["filename"],
            "output_text": job_output["output_text"],
            "download_url": f"/download/job-output/{job_output['job_id']}",
        })

    return _render_job_result("Add Secondary Device - Jabber for iPhone (Option 3)", data, filename, back_url=back_url or "/menu")


@app.post("/add/secondary-bot-device")
def add_secondary_bot_device_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    back_url: str = Form("/menu"),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    data, filename = add_secondary_bot_device(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )
    try:
      notify_status, notify_details = _send_mobile_jabber_ready_email_if_built(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
        csv_data=data,
        created_steps={"Add BOT Device"},
      )
    except Exception as exc:
      notify_status, notify_details = "Failed", f"Email notification failed: {exc}"
    data = _append_result_row(data, "Notify End User", notify_status, notify_details)
    _append_audit_event(
      action="add_secondary_bot_option_4",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=target_user,
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
        job_output = _prepare_job_output(data, filename)
        return JSONResponse({
            "job_id": job_output["job_id"],
            "filename": job_output["filename"],
            "output_text": job_output["output_text"],
            "download_url": f"/download/job-output/{job_output['job_id']}",
        })

    return _render_job_result("Add Secondary Device - Jabber for Android (Option 4)", data, filename, back_url=back_url or "/menu")


@app.post("/add/secondary-strike-devices")
def add_secondary_strike_devices_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    data, filename = add_secondary_strike_devices(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )
    try:
      notify_status, notify_details = _send_mobile_jabber_ready_email_if_built(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
        csv_data=data,
        created_steps={"Add TCT Device", "Add BOT Device"},
      )
    except Exception as exc:
      notify_status, notify_details = "Failed", f"Email notification failed: {exc}"
    data = _append_result_row(data, "Notify End User", notify_status, notify_details)
    _append_audit_event(
      action="add_secondary_strike_option_5",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=target_user,
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
        job_output = _prepare_job_output(data, filename)
        return JSONResponse({
            "job_id": job_output["job_id"],
            "filename": job_output["filename"],
            "output_text": job_output["output_text"],
            "download_url": f"/download/job-output/{job_output['job_id']}",
        })

    return _render_job_result("STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)", data, filename, back_url="/menu-admin")


@app.post("/delete/secondary-mobile-devices")
def delete_secondary_mobile_devices_route(
  request: Request,
  cucm_host: str = Form(""),
  cucm_user: str = Form(""),
  cucm_pass: str = Form(""),
  target_user: str = Form(...),
  remove_tct: str = Form("0"),
  remove_bot: str = Form("0"),
  inline: bool = Query(False),
):
  cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
  _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

  remove_tct_enabled = (remove_tct or "").strip().lower() in {"1", "true", "yes", "on"}
  remove_bot_enabled = (remove_bot or "").strip().lower() in {"1", "true", "yes", "on"}

  data, filename = delete_secondary_mobile_devices(
    cucm_host=cucm_host,
    cucm_user=cucm_user,
    cucm_pass=cucm_pass,
    target_user=target_user,
    remove_tct=remove_tct_enabled,
    remove_bot=remove_bot_enabled,
  )

  _append_audit_event(
    action="delete_secondary_mobile_devices",
    cucm_host=cucm_host,
    operator=cucm_user,
    target=f"{target_user};remove_tct={str(remove_tct_enabled).lower()};remove_bot={str(remove_bot_enabled).lower()}",
    output_filename=filename,
    inline_mode=inline,
  )

  if inline:
    job_output = _prepare_job_output(data, filename)
    return JSONResponse({
      "job_id": job_output["job_id"],
      "filename": job_output["filename"],
      "output_text": job_output["output_text"],
      "download_url": f"/download/job-output/{job_output['job_id']}",
    })

  return _render_job_result("Remove only Jabber Mobile - iPhone or Android", data, filename, back_url="/menu-admin")


@app.post("/line-groups/edit-members")
def edit_line_group_members_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    line_group_name: str = Form(...),
    membership_action: str = Form(...),
    dn_pattern: str = Form(...),
    dn_partition: str = Form("ENT_DEVICE_PT"),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    data, filename = edit_line_group_members(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        line_group_name=line_group_name,
        action=membership_action,
        dn_pattern=dn_pattern,
        dn_partition=dn_partition,
    )
    _append_audit_event(
      action="edit_line_group_members_option_17",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=f"{line_group_name} [{membership_action}] {dn_pattern}/{dn_partition}",
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
      job_output = _prepare_job_output(data, filename)
      return JSONResponse({
        "job_id": job_output["job_id"],
        "filename": job_output["filename"],
        "output_text": job_output["output_text"],
        "download_url": f"/download/job-output/{job_output['job_id']}",
      })

    return _render_job_result("Edit Line Group Members (Option 17)", data, filename, back_url="/menu-admin")


@app.post("/line-groups/search")
def search_line_groups_route(
  request: Request,
  cucm_host: str = Form(""),
  cucm_user: str = Form(""),
  cucm_pass: str = Form(""),
  line_group_search: str = Form(""),
):
  cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
  _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
  matches = search_line_groups(
    cucm_host=cucm_host,
    cucm_user=cucm_user,
    cucm_pass=cucm_pass,
    search_text=line_group_search,
  )
  return JSONResponse({"matches": matches})


@app.post("/export/rpo-phones")
def extract_rpo_phones_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    rpo_userids: str = Form(...),
    inline: bool = Query(False),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
    data, filename = extract_rpo_phones(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        userids_text=rpo_userids,
    )
    target_count = len([u for u in (rpo_userids or "").splitlines() if u.strip()])
    _append_audit_event(
      action="extract_rpo_phones_option_18",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=f"user_count={target_count}",
      output_filename=filename,
      inline_mode=inline,
    )

    if inline:
      job_output = _prepare_job_output(data, filename)
      return JSONResponse({
        "job_id": job_output["job_id"],
        "filename": job_output["filename"],
        "output_text": job_output["output_text"],
        "download_url": f"/download/job-output/{job_output['job_id']}",
      })

    return _render_job_result("Extract RPO Phones (Option 18)", data, filename, back_url="/menu-admin")

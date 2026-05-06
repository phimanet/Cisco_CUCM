import csv
import datetime
import os
import threading
import time

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
from toolkit.build_user_csf_phone import build_user_csf_phone_from_template
from toolkit.decommission_user_csf_voicemail import decommission_user_csf_voicemail
from toolkit.reset_unity_voicemail_pin import reset_unity_voicemail_pin
from toolkit.add_secondary_devices import (
  add_secondary_tct_device,
  add_secondary_bot_device,
  add_secondary_strike_devices,
)

app = FastAPI(title="Cisco Voice Server Automation Site - Restricted Access")
JOB_OUTPUTS = {}
AUTH_SESSIONS = {}
SESSION_COOKIE_NAME = "cucm_web_session"
SESSION_IDLE_TIMEOUT_SECONDS = 8 * 60 * 60
PROD_CUCM_HOST = "lascucmpp01.ahs.int"
LAB_CUCM_HOST = "lascucmpl01.ahs.int"
PROD_UNITY_HOST = "SANCUTYP01.ahs.int"
LAB_UNITY_HOST = "lascutypl01.ahs.int"
AUDIT_LOG_LOCK = threading.Lock()
AUDIT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
AUDIT_RETENTION_DAYS = 365
AUDIT_FIELDS = [
  "timestamp",
  "action",
  "cucm_host",
  "operator",
  "target",
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
  return path in {"/", "/login"}


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

  cutoff = datetime.datetime.now() - datetime.timedelta(days=AUDIT_RETENTION_DAYS)
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
):
  row = [
    datetime.datetime.now().strftime(AUDIT_TIMESTAMP_FORMAT),
    action,
    cucm_host,
    operator,
    target,
    output_filename,
    str(bool(inline_mode)).lower(),
  ]

  with AUDIT_LOG_LOCK:
    _ensure_audit_log()
    _prune_audit_log_locked()
    with open(AUDIT_LOG_PATH, "a", newline="", encoding="utf-8") as handle:
      writer = csv.writer(handle)
      writer.writerow(row)


def _to_bytes(data):
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    return str(data).encode("utf-8")


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


def _render_job_result(title: str, csv_data, filename: str) -> HTMLResponse:
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
        <p><a href="/menu">Back to Menu</a></p>
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
    </section>
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
  auth_user = escape(str(session.get("username", "")))
  auth_cucm_host = str(session.get("cucm_host", ""))
  env_text, env_css_class = _get_environment_label(auth_cucm_host)
  return """
<html>
  <head>
    <title>Cisco Voice Server Automation Site - Restricted Access</title>
    <style>
      :root {
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-sky: #eaf4ff;
        --amn-text: #12304a;
        --amn-border: #c8dbee;
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
        padding: 14px 24px;
        background: linear-gradient(90deg, var(--amn-navy), var(--amn-blue));
        color: #fff;
        box-shadow: 0 2px 12px rgba(0, 47, 108, 0.25);
      }

      .topbar-brand {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .topbar-actions {
        display: flex;
        align-items: center;
        gap: 10px;
      }

      .topbar-btn {
        display: inline-block;
        padding: 10px 18px;
        border-radius: 10px;
        font-size: 14px;
        font-weight: 700;
        text-decoration: none;
        border: 1px solid rgba(255, 255, 255, 0.65);
      }

      .topbar-btn-login {
        color: #fff;
        background: rgba(255, 255, 255, 0.14);
      }

      .topbar-btn-logout {
        color: #fff;
        background: #b42318;
        border-color: #fda29b;
      }

      .topbar-btn:hover {
        filter: brightness(1.06);
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

      .content {
        max-width: 1400px;
        margin: 18px auto 24px auto;
        padding: 0 16px;
      }

      .env-banner {
        display: inline-block;
        margin: 8px 0 14px 0;
        padding: 10px 16px;
        border-radius: 10px;
        font-weight: 800;
        letter-spacing: 0.2px;
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
        margin: 18px 0 10px 0;
        color: var(--amn-navy);
      }

      form,
      .build-user-output,
      .offboard-output,
      .secondary-output {
        background: #fff;
        border: 1px solid var(--amn-border);
        border-radius: 10px;
        padding: 14px;
        box-shadow: 0 6px 16px rgba(0, 47, 108, 0.07);
      }

      input,
      select,
      button,
      textarea {
        border-radius: 8px;
        border: 1px solid var(--amn-border);
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

      a {
        color: var(--amn-blue);
      }

      hr {
        border: none;
        border-top: 1px solid var(--amn-border);
        margin: 22px 0;
      }

      .build-user-layout {
        display: flex;
        gap: 24px;
        align-items: flex-start;
        flex-wrap: wrap;
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
        height: 380px;
        font-family: Consolas, monospace;
        background: var(--amn-sky);
        color: #0f2940;
      }

      .build-user-status {
        color: #2c5c8a;
        min-height: 18px;
      }

      .offboard-layout {
        display: flex;
        gap: 24px;
        align-items: flex-start;
        flex-wrap: wrap;
      }

      .offboard-form {
        flex: 1 1 420px;
        min-width: 320px;
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
        height: 380px;
        font-family: Consolas, monospace;
        background: var(--amn-sky);
        color: #0f2940;
      }

      .offboard-status {
        color: #2c5c8a;
        min-height: 18px;
      }

      .secondary-layout {
        display: flex;
        gap: 24px;
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
        height: 380px;
        font-family: Consolas, monospace;
        background: var(--amn-sky);
        color: #0f2940;
      }

      .secondary-status {
        color: #2c5c8a;
        min-height: 18px;
      }

      @media (max-width: 980px) {
        .build-user-output textarea {
          height: 280px;
        }

        .offboard-output textarea {
          height: 280px;
        }

        .secondary-output textarea {
          height: 280px;
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
    <h2>Cisco Voice Server Automation Site - Restricted Access</h2>
    <p>Authenticated as: <strong>__AUTH_USER__</strong></p>
    <div class="env-banner __ENV_CLASS__">__ENV_TEXT__</div>
    <p><a href="/">Back to Landing Page</a></p>
    <p>Environment was selected at login and is locked for this session.</p>
    <p>Security mode: passwords are not cached server-side. Enter admin password for each action.</p>
    <p><a href="/download/audit-trail">Download Audit Trail (CSV)</a></p>

    <h3>Build Cisco Jabber Laptop and Voicemail - New Hire or New Jabber Laptop/VM Add</h3>

    <div class="build-user-layout">
      <form id="build-user-form" class="target-user-form build-user-form" action="/build/user-csf-phone" method="post">
        Cisco Callmanager Username:<br>
        <input name="cucm_user" value="__AUTH_USER__" required><br><br>

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
          <button type="submit">Run Build User CSF Phone</button>
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

    <hr>

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

    <hr>

    <h3>Offboard User - Delete all Jabber and Voicemail Box (Option 10)</h3>

    <div class="offboard-layout">
      <form id="offboard-user-form" class="target-user-form offboard-form" action="/decommission/user-csf-voicemail" method="post">
        Cisco Callmanager Username:<br>
        <input name="cucm_user" value="__AUTH_USER__" required><br><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to Offboard:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button type="submit">Run Offboard User - Delete all Jabber and Voicemail Box (Option 10)</button>
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

    <hr>

    <h3>Add Secondary Device - Jabber for iPhone (Option 3)</h3>

    <div class="secondary-layout">
      <form id="secondary-tct-form" class="target-user-form secondary-form" action="/add/secondary-tct-device" method="post">
        Cisco Callmanager Username:<br>
        <input name="cucm_user" value="__AUTH_USER__" required><br><br>

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

    <hr>

    <h3>Add Secondary Device - Jabber for Android (Option 4)</h3>

    <div class="secondary-layout">
      <form id="secondary-bot-form" class="target-user-form secondary-form" action="/add/secondary-bot-device" method="post">
        Cisco Callmanager Username:<br>
        <input name="cucm_user" value="__AUTH_USER__" required><br><br>

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

    <hr>

    <h3>STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)</h3>

    <div class="secondary-layout">
      <form id="secondary-strike-form" class="target-user-form secondary-form" action="/add/secondary-strike-devices" method="post">
        Cisco Callmanager Username:<br>
        <input name="cucm_user" value="__AUTH_USER__" required><br><br>

        Cisco Callmanager Password:<br>
        <input type="password" name="cucm_pass" required><br><br>

        User ID for person to add STRIKE MODE devices for:<br>
        <input name="target_user" placeholder="john.doe" required><br><br>

        <div class="action-row">
          <button type="submit">Run STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="secondary-output" aria-live="polite">
        <h4>Option 5 Output Preview</h4>
        <p id="secondary-strike-status" class="secondary-status">Run Option 5 to view output here.</p>
        <p>
          <a id="secondary-strike-download" href="#" style="color:#7ec8ff; font-weight:bold; display:none;">
            Download CSV Output
          </a>
        </p>
        <textarea id="secondary-strike-preview" readonly></textarea>
      </section>
    </div>

    <hr>

    <h3>Add Directory Numbers (Upload CSV)</h3>

    <form action="/add/directorynumbers" method="post" enctype="multipart/form-data">
      Cisco Callmanager Username:<br>
      <input name="cucm_user" value="__AUTH_USER__" required><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass" required><br><br>

      CSV File:<br>
      <input type="file" name="csv_file" required><br><br>

      <a href="/download/add-directorynumbers-template">Download CSV Template</a><br><br>

      <div class="action-row">
        <button type="submit">Run Add Directory Numbers</button>
        <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
      </div>
    </form>

    <hr>

    <h3>Export Directory Numbers</h3>

    <form action="/export/directorynumbers" method="post">
      Cisco Callmanager Username:<br>
      <input name="cucm_user" value="__AUTH_USER__" required><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass" required><br><br>

      DN Pattern (supports %):<br>
      <input name="dn_contains"><br><br>

      Route Partition (optional):<br>
      <input name="route_partition"><br><br>

      <button type="submit">Export Directory Numbers</button>
    </form>

    <hr>

    <h3>Export End Users</h3>

    <form action="/export/endusers" method="post">
      Cisco Callmanager Username:<br>
      <input name="cucm_user" value="__AUTH_USER__" required><br><br>

      Cisco Callmanager Password:<br>
      <input type="password" name="cucm_pass" required><br><br>

      Last Name:<br>
      <input name="lastname"><br><br>

      <button type="submit">Export End Users</button>
    </form>

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

          const targetUserInput = form.querySelector('input[name="target_user"]');
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
            submitBuildUserInline(form);
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

          if (form.id === "secondary-tct-form") {
            event.preventDefault();
            submitSecondaryInline(form, {
              statusId: "secondary-tct-status",
              previewId: "secondary-tct-preview",
              downloadId: "secondary-tct-download",
              runningText: "Running Option 3...",
              failedText: "Option 3 failed. Review output and retry.",
              defaultFilename: "option3_output.csv",
            });
            return;
          }

          if (form.id === "secondary-bot-form") {
            event.preventDefault();
            submitSecondaryInline(form, {
              statusId: "secondary-bot-status",
              previewId: "secondary-bot-preview",
              downloadId: "secondary-bot-download",
              runningText: "Running Option 4...",
              failedText: "Option 4 failed. Review output and retry.",
              defaultFilename: "option4_output.csv",
            });
            return;
          }

          if (form.id === "secondary-strike-form") {
            event.preventDefault();
            submitSecondaryInline(form, {
              statusId: "secondary-strike-status",
              previewId: "secondary-strike-preview",
              downloadId: "secondary-strike-download",
              runningText: "Running Option 5...",
              failedText: "Option 5 failed. Review output and retry.",
              defaultFilename: "option5_output.csv",
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
    </script>
    </main>
  </body>
</html>
""".replace("__AUTH_USER__", auth_user).replace("__ENV_TEXT__", escape(env_text)).replace("__ENV_CLASS__", env_css_class)


@app.get("/download/add-directorynumbers-template")
def download_add_directorynumbers_template():
  template_csv = "pattern\n5551001\n5551002\n"
  return Response(
    template_csv.encode("utf-8"),
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="add_directory_numbers_template.csv"'}
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
    return _render_job_result("Add Directory Numbers", log_csv, filename)


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
    return _render_job_result("Export Directory Numbers", data, filename)


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
    return _render_job_result("Export End Users", data, filename)


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
    data, filename = build_user_csf_phone_from_template(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
        dn_type=dn_type,
    )
    _append_audit_event(
      action="build_user_csf_phone",
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

    return _render_job_result("Build User CSF Phone", data, filename)


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
    data, filename = decommission_user_csf_voicemail(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=target_user,
    )
    _append_audit_event(
      action="offboard_user_option_10",
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


@app.post("/add/secondary-tct-device")
def add_secondary_tct_device_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
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

    return _render_job_result("Add Secondary Device - Jabber for iPhone (Option 3)", data, filename)


@app.post("/add/secondary-bot-device")
def add_secondary_bot_device_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
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

    return _render_job_result("Add Secondary Device - Jabber for Android (Option 4)", data, filename)


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

    return _render_job_result("STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)", data, filename)

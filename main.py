import csv
import datetime
import hashlib
import io
import json
import logging
import os
import re
import socket
import subprocess
import tempfile
from collections import Counter
import smtplib
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from email.message import EmailMessage
from zoneinfo import ZoneInfo
from xml.sax.saxutils import escape as xml_escape

import requests
import urllib3
try:
  from cryptography.fernet import Fernet, InvalidToken
  _FERNET_AVAILABLE = True
except Exception:
  Fernet = None
  InvalidToken = Exception
  _FERNET_AVAILABLE = False
from fastapi import FastAPI, Form, UploadFile, File, Query, Request
from fastapi.responses import HTMLResponse, Response, JSONResponse, RedirectResponse
from html import escape, unescape
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin
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
from toolkit.translation_pattern_lookup import (
  lookup_translation_patterns,
  build_translation_pattern_template,
  get_translation_pattern_full,
)
from toolkit.create_teams_telephony_user import create_teams_telephony_user
from toolkit.remove_teams_telephony_user import (
  lookup_teams_telephony_removal_candidate,
  remove_teams_telephony_user,
)

logger = logging.getLogger(__name__)

app = FastAPI(title="Cisco Voice Server Automation Site - Restricted Access")
JOB_OUTPUTS = {}
VERASMART_QUEUE_RUNS = {}
VERASMART_QUEUE_LOCK = threading.Lock()
VERASMART_QUEUE_MAX_RUNS = 50
STRIKE_MASK_OPERATIONS = {}
STRIKE_MASK_LOCK = threading.Lock()
STRIKE_MASK_MAX_OPERATIONS = 200
CERT_RENEWAL_RUNS = {}
CERT_RENEWAL_RUNS_LOCK = threading.Lock()
CERT_RENEWAL_MAX_RUNS = 200
AUTH_SESSIONS = {}
AUTH_SESSION_SECRETS = {}
TWILIO_INCOMING_PHONE_NUMBER_CACHE = {}
TWILIO_INCOMING_PHONE_NUMBER_CACHE_LOCK = threading.Lock()
TWILIO_INCOMING_PHONE_NUMBER_CACHE_TTL_SECONDS = 5 * 60
INTEGRATION_FEASIBILITY_CACHE = {}
INTEGRATION_FEASIBILITY_LOCK = threading.Lock()
INTEGRATION_FEASIBILITY_TTL_SECONDS = 5 * 60
SESSION_COOKIE_NAME = "cucm_web_session"
SESSION_IDLE_TIMEOUT_SECONDS = 8 * 60 * 60
CREDENTIAL_CACHE_TTL_SECONDS = 60 * 60
APP_START_EPOCH = time.time()
CREDENTIAL_ENCRYPTION_KEY = (os.getenv("CUCM_CREDENTIAL_ENCRYPTION_KEY", "") or "").strip()
if _FERNET_AVAILABLE and not CREDENTIAL_ENCRYPTION_KEY:
  # Generate an in-memory key when env key is absent so caching is still encrypted.
  CREDENTIAL_ENCRYPTION_KEY = Fernet.generate_key().decode("utf-8")
_CREDENTIAL_CIPHER = None
if _FERNET_AVAILABLE and CREDENTIAL_ENCRYPTION_KEY:
  try:
    _CREDENTIAL_CIPHER = Fernet(CREDENTIAL_ENCRYPTION_KEY.encode("utf-8"))
  except Exception:
    _CREDENTIAL_CIPHER = None
PROD_CUCM_HOST = "lascucmpp01.ahs.int"
LAB_CUCM_HOST = "lascucmpl01.ahs.int"
PROD_UNITY_HOST = "SANCUTYP01.ahs.int"
LAB_UNITY_HOST = "lascutypl01.ahs.int"
PROD_LDAP_AGREEMENT = "LDAP_AMN"
LAB_LDAP_AGREEMENT = "LAB_LDAP_AMN"
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
AUDIT_LOG_EMAIL_DOMAIN = (os.getenv("AUDIT_LOG_EMAIL_DOMAIN", "amnhealthcare.com") or "amnhealthcare.com").strip().lstrip("@")
TWILIO_ACCOUNT_SID = (os.getenv("TWILIO_ACCOUNT_SID", "") or "").strip()
TWILIO_AUTH_TOKEN = (os.getenv("TWILIO_AUTH_TOKEN", "") or "").strip()
TWILIO_SUBACCOUNT_SID = (os.getenv("TWILIO_SUBACCOUNT_SID", "") or "").strip()
TWILIO_SUBACCOUNT_AUTH_TOKEN = (os.getenv("TWILIO_SUBACCOUNT_AUTH_TOKEN", "") or "").strip()
TWILIO_SUBACCOUNT_NAME = (os.getenv("TWILIO_SUBACCOUNT_NAME", "AMNOne-Notification-PROD") or "AMNOne-Notification-PROD").strip()
TWILIO_SALESFORCE_SUBACCOUNT_SID = (os.getenv("TWILIO_SALESFORCE_SUBACCOUNT_SID", "") or "").strip()
TWILIO_SALESFORCE_AUTH_TOKEN = (os.getenv("TWILIO_SALESFORCE_AUTH_TOKEN", "") or "").strip()
TWILIO_SALESFORCE_SUBACCOUNT_NAME = (os.getenv("TWILIO_SALESFORCE_SUBACCOUNT_NAME", "Enterprise Org Prod") or "Enterprise Org Prod").strip()
TWILIO_AMIEWEB_DEFAULT_SMS_URL = (
  os.getenv("TWILIO_AMIEWEB_DEFAULT_SMS_URL", "https://api.amnhealthcare.io/listener/notification/v1/twilio/listener")
  or "https://api.amnhealthcare.io/listener/notification/v1/twilio/listener"
).strip()
TWILIO_AMIEWEB_MESSAGING_SERVICE_SID = (
  os.getenv("TWILIO_AMIEWEB_MESSAGING_SERVICE_SID", "MGdd208368e216d6c6cbd79a90ee4320b8")
  or "MGdd208368e216d6c6cbd79a90ee4320b8"
).strip()
TWILIO_HOSTED_NUMBERS_ACTIVE = (os.getenv("TWILIO_HOSTED_NUMBERS_ACTIVE", "false") or "false").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
GENESYS_CLOUD_REGION = (os.getenv("GENESYS_CLOUD_REGION", "usw2") or "usw2").strip().lower()
GENESYS_CLIENT_ID = (os.getenv("GENESYS_CLIENT_ID", "") or "").strip()
GENESYS_CLIENT_SECRET = (os.getenv("GENESYS_CLIENT_SECRET", "") or "").strip()
GENESYS_USERS_PAGE_SIZE = int((os.getenv("GENESYS_USERS_PAGE_SIZE", "100") or "100").strip())
GENESYS_PHONE_LOOKUP_MAX_PAGES = int((os.getenv("GENESYS_PHONE_LOOKUP_MAX_PAGES", "50") or "50").strip())
GENESYS_QUEUE_LOOKUP_MAX_PAGES = int((os.getenv("GENESYS_QUEUE_LOOKUP_MAX_PAGES", "30") or "30").strip())
GENESYS_QUEUE_MEMBER_MAX_PAGES = int((os.getenv("GENESYS_QUEUE_MEMBER_MAX_PAGES", "20") or "20").strip())
GENESYS_QUEUE_ID_PATTERN = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
GENESYS_PRIORITY_QUEUE_IDS = [
  (item or "").strip()
  for item in (os.getenv("GENESYS_PRIORITY_QUEUE_IDS", "df95c0ce-1ca4-4ab1-8ce3-f474642edf4d") or "df95c0ce-1ca4-4ab1-8ce3-f474642edf4d").split(",")
  if (item or "").strip()
]
AERIALINK_V5_BASE_URL = (os.getenv("AERIALINK_V5_BASE_URL", "https://apix5.aerialink.net/v5") or "https://apix5.aerialink.net/v5").strip().rstrip("/")
AERIALINK_USERNAME = (os.getenv("AERIALINK_USERNAME", "") or "").strip()
AERIALINK_PASSWORD = (os.getenv("AERIALINK_PASSWORD", "") or "").strip()
AERIALINK_ACCOUNT_CODE_LOOKUP_PATH = (os.getenv("AERIALINK_ACCOUNT_CODE_LOOKUP_PATH", "/codes") or "/codes").strip()
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
STRIKE_MASK_PATTERN_PREFIX = (os.getenv("STRIKE_MASK_PATTERN_PREFIX", "945") or "945").strip()
STRIKE_MASK_ROUTE_PARTITION = "ENT_DEVICE_PT"
STRIKE_MASK_AVAILABLE_TRANSFORM_MASK = "2481001"
SMS_NUMBER_LOOKUP_ENABLED = (os.getenv("SMS_NUMBER_LOOKUP_ENABLED", "true") or "true").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
PREVIEW_FEATURES_LAB_ONLY_DEFAULT = (os.getenv("PREVIEW_FEATURES_LAB_ONLY_DEFAULT", "true") or "true").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
SMS_EXPERIMENTAL_MENU_ENABLED = (os.getenv("SMS_EXPERIMENTAL_MENU_ENABLED", "false") or "false").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
SMS_EXPERIMENTAL_MENU_LAB_ONLY = (os.getenv("SMS_EXPERIMENTAL_MENU_LAB_ONLY", "true") or "true").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
CERT_MANAGER_PAGE_ENABLED = (os.getenv("CERT_MANAGER_PAGE_ENABLED", "true") or "true").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
CERT_MANAGER_PAGE_LAB_ONLY = (os.getenv("CERT_MANAGER_PAGE_LAB_ONLY", "true") or "true").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
INTEGRATION_PREFLIGHT_REQUIRED = (os.getenv("INTEGRATION_PREFLIGHT_REQUIRED", "true") or "true").strip().lower() in {
  "1",
  "true",
  "yes",
  "on",
}
LAB_CERT_MANAGER_TARGETS = [
  {
    "system": "CUCM",
    "role": "Publisher",
    "hostname": "lascucmpl01.ahs.int",
    "ip": "10.241.18.200",
  },
  {
    "system": "CUCM",
    "role": "Subscriber",
    "hostname": "lascucmsl01.ahs.int",
    "ip": "10.241.18.201",
  },
  {
    "system": "IM and Presence",
    "role": "Publisher",
    "hostname": "lascucimppl01.ahs.int",
    "ip": "10.241.18.204",
  },
  {
    "system": "IM and Presence",
    "role": "Subscriber",
    "hostname": "lascucimpsl01.ahs.int",
    "ip": "10.241.18.205",
  },
  {
    "system": "Unity Voicemail",
    "role": "Publisher",
    "hostname": "lascutypl01.ahs.int",
    "ip": "10.241.18.202",
  },
  {
    "system": "Unity Voicemail",
    "role": "Subscriber",
    "hostname": "lascutysl01.ahs.int",
    "ip": "10.241.18.203",
  },
]
LAB_CERT_MANAGER_ALLOWED_HOSTS = {
  str(item.get("hostname", "") or "").strip().lower()
  for item in LAB_CERT_MANAGER_TARGETS
  if str(item.get("hostname", "") or "").strip()
}
CERT_MANAGER_PROBE_PORTS = [8443, 443]
CSF_JABBER_EMAIL_FROM = "noreply@amnhealthcare.com"
TWILIO_INBOUND_VERIFICATION_PROFILES = {
  "phimane": {
    "panel_label": "Twilio-Inbound-Verificaton-Phimane",
    "description": "Twilio Number Verification to Phimane 8585236648",
    "home_pattern": "8585236648",
  },
  "lauraa": {
    "panel_label": "Twilio-Inbound-Verificaton-LauraA",
    "description": "Twilio Number Verification to LauraA 8583503289",
    "home_pattern": "8583503289",
  },
}
TWILIO_INBOUND_AUTO_RESTORE_SECONDS = 5 * 60
TWILIO_INBOUND_AUTO_RESTORE_LOCK = threading.Lock()
TWILIO_INBOUND_AUTO_RESTORE_TIMERS: dict[str, dict] = {}
CSF_JABBER_EMAIL_FROM = (os.getenv("CSF_JABBER_EMAIL_FROM", MOBILE_JABBER_EMAIL_FROM) or MOBILE_JABBER_EMAIL_FROM).strip()
CSF_JABBER_TRAINING_URL = (
  "https://amnhealthcare.sharepoint.com/teams/AMNITTrainingContent-tm/_layouts/15/stream.aspx?id=%2Fteams%2FAMNITTrainingContent%2Dtm%2FShared%20Documents%2FGeneral%2FWatch%20and%20Learn%20Cisco%20Jabber%20Softphone%2012%2E9%2Emp4&referrer=StreamWebApp%2EWeb&referrerScenario=AddressBarCopied%2Eview%2Ef9fafd5b%2D7aeb%2D4bfb%2Dbc57%2Dda61d14ef75f"
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
TWILIO_SMS_HOSTING_AUDIT_LOCK = threading.Lock()
TWILIO_SMS_HOSTING_AUDIT_FIELDS = [
  "timestamp",
  "submitter",
  "session_friendly_name",
  "input_number",
  "normalized_number",
  "phone_sid",
  "verification_code",
  "verification_status",
  "result_action",
  "result_status",
  "loa_mode",
  "loa_batch_reference",
  "loa_recipient_name",
  "loa_recipient_email",
  "loa_recipient_phone",
  "messaging_service_sid",
  "messaging_service_status",
]
TWILIO_SMS_HOSTING_AUDIT_PATH = os.path.join(
  os.path.dirname(os.path.abspath(__file__)),
  "logs",
  "twilio_sms_hosting_audit.csv",
)
TWILIO_SMS_HOSTING_AUDIT_RETENTION_DAYS = int(
  (os.getenv("TWILIO_SMS_HOSTING_AUDIT_RETENTION_DAYS", "90") or "90").strip()
)
GENESYS_WEBRTC_TEMPLATE_PATH = os.path.join(
  os.path.dirname(os.path.abspath(__file__)),
  "toolkit",
  "genesys_webrtc_phone_template.json",
)
STRIKE_MASK_HISTORY_LOCK = threading.Lock()
STRIKE_MASK_HISTORY_FIELDS = [
  "timestamp",
  "event",
  "operation_id",
  "cucm_host",
  "operator",
  "target_user",
  "translation_pattern",
  "translation_pattern_partition",
  "device_name",
  "device_type",
  "line_mask_status",
  "detail",
]
STRIKE_MASK_HISTORY_PATH = os.path.join(
  os.path.dirname(os.path.abspath(__file__)),
  "logs",
  "strike_mask_history.csv",
)
SETTINGS_FILE_PATH = os.path.join(
  os.path.dirname(os.path.abspath(__file__)),
  "settings.json",
)
DEFAULT_SETTINGS = {
  "general_fte_prefix": "945",
  "strike_prefix": "817",
  "recruiter_prefix": "469",
  "twilio_loa_recipient_name": "Laura Alvarez",
  "twilio_loa_recipient_email": "laura.alvarez@amnhealthare.com",
  "twilio_loa_recipient_phone": "+18583503289",
  # Separation SMS report scheduler (editable via Page 2 panel)
  "sep_report_enabled": "true",
  "sep_report_recipient": "",
  "sep_report_recipient_2": "",
  "sep_report_from": "",
  "sep_report_hour": "",
  "sep_report_minute": "",
  "sep_report_frequency": "",
  "sep_report_weekly_day": "",
  # DN Availability report scheduler (editable via Page 2 panel)
  "dn_report_enabled": "true",
  "dn_report_recipient": "",
  "dn_report_recipient_2": "",
  "dn_report_from": "",
  "dn_report_hour": "8",
  "dn_report_minute": "0",
  "dn_report_frequency": "daily",
  "dn_report_cucm_host": "",
  "dn_report_cucm_user": "ucmappadmin",
  "dn_report_cucm_pass": "abi3rto!",
  "dn_report_low_threshold": "10",
}
SETTINGS_LOCK = threading.Lock()

# --- Separation SMS Report Scheduler ---
SEPARATION_REPORT_ENABLED = (os.getenv("SEPARATION_REPORT_ENABLED", "true") or "true").strip().lower() in {
  "1", "true", "yes", "on",
}
SEPARATION_REPORT_RECIPIENT = (
  os.getenv("SEPARATION_REPORT_RECIPIENT", "Laura.Alvarez@amnhealthcare.com")
  or "Laura.Alvarez@amnhealthcare.com"
).strip()
# Optional second recipient — leave blank to disable.
SEPARATION_REPORT_RECIPIENT_2 = (os.getenv("SEPARATION_REPORT_RECIPIENT_2", "") or "").strip()
SEPARATION_REPORT_FROM = (
  os.getenv("SEPARATION_REPORT_FROM", "noreply@amnhealthcare.com")
  or "noreply@amnhealthcare.com"
).strip()
# Hour and minute in PST/PDT (America/Los_Angeles) to send the report.
SEPARATION_REPORT_HOUR = int((os.getenv("SEPARATION_REPORT_HOUR", "8") or "8").strip())
SEPARATION_REPORT_MINUTE = int((os.getenv("SEPARATION_REPORT_MINUTE", "0") or "0").strip())
# "daily" or "weekly"
SEPARATION_REPORT_FREQUENCY = (os.getenv("SEPARATION_REPORT_FREQUENCY", "daily") or "daily").strip().lower()
# For weekly mode: day name the report fires (e.g. "monday"). The window spans Mon–Sun of the prior week.
SEPARATION_REPORT_WEEKLY_DAY = (os.getenv("SEPARATION_REPORT_WEEKLY_DAY", "monday") or "monday").strip().lower()
_SEPARATION_REPORT_SCHEDULER_LAST_FIRED: dict[str, str] = {}
_SEPARATION_REPORT_SCHEDULER_LOCK = threading.Lock()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _prune_auth_sessions_locked(now_epoch: float):
  expired = [
    sid
    for sid, data in AUTH_SESSIONS.items()
    if (
      (now_epoch - float(data.get("last_seen", 0))) > SESSION_IDLE_TIMEOUT_SECONDS
      or now_epoch > float(data.get("credential_expires_at", 0) or 0)
    )
  ]
  for sid in expired:
    AUTH_SESSIONS.pop(sid, None)
    AUTH_SESSION_SECRETS.pop(sid, None)


def _cache_secret(session: dict, key: str, value: str, now_epoch: float | None = None):
  if not session:
    return
  cleaned = (value or "").strip()
  if not cleaned:
    return
  now = now_epoch if now_epoch is not None else time.time()
  if _CREDENTIAL_CIPHER:
    token = _CREDENTIAL_CIPHER.encrypt(cleaned.encode("utf-8")).decode("utf-8")
    session[f"{key}_enc"] = token
    # Keep an in-memory fallback copy to tolerate cache-metadata edge cases.
    session[key] = cleaned
  else:
    # Compatibility fallback: keep service running if cryptography is unavailable.
    session[key] = cleaned
    session.pop(f"{key}_enc", None)
  session[f"{key}_cached_at"] = now
  session["credential_expires_at"] = now + CREDENTIAL_CACHE_TTL_SECONDS


def _get_cached_secret(session: dict, key: str, now_epoch: float | None = None) -> str:
  if not session:
    return ""

  now = now_epoch if now_epoch is not None else time.time()
  expires_at = float(session.get("credential_expires_at", 0) or 0)
  cached_at = float(session.get(f"{key}_cached_at", 0) or 0)
  encrypted_value = (session.get(f"{key}_enc", "") or "").strip()
  legacy_plain_value = (session.get(key, "") or "").strip()

  if not encrypted_value and not legacy_plain_value:
    return ""

  # Only expire by absolute time when an expiry timestamp exists.
  if expires_at and now > expires_at:
    session.pop(key, None)
    session.pop(f"{key}_enc", None)
    session.pop(f"{key}_cached_at", None)
    return ""

  # Only expire by TTL delta when we have a cache timestamp.
  if cached_at and (now - cached_at) > CREDENTIAL_CACHE_TTL_SECONDS:
    session.pop(key, None)
    session.pop(f"{key}_enc", None)
    session.pop(f"{key}_cached_at", None)
    return ""

  if encrypted_value:
    if not _CREDENTIAL_CIPHER:
      session.pop(f"{key}_enc", None)
      session.pop(f"{key}_cached_at", None)
      return ""
    try:
      return _CREDENTIAL_CIPHER.decrypt(encrypted_value.encode("utf-8")).decode("utf-8").strip()
    except (InvalidToken, ValueError, TypeError):
      session.pop(f"{key}_enc", None)
      session.pop(f"{key}_cached_at", None)
      return ""

  # Backward-compatible migration for sessions created before encryption was added.
  if legacy_plain_value:
    _cache_secret(session, key, legacy_plain_value, now)
    session.pop(key, None)
    return legacy_plain_value

  return ""


def _has_valid_cached_secret(session: dict, key: str, now_epoch: float | None = None) -> bool:
  return bool(_get_cached_secret(session, key, now_epoch))


def _genesys_region_to_urls(region: str) -> tuple[str, str, str]:
  clean_region = (region or "").strip().lower() or GENESYS_CLOUD_REGION or "usw2"
  login_base = f"https://login.{clean_region}.pure.cloud"
  api_base = f"https://api.{clean_region}.pure.cloud"
  return clean_region, login_base, api_base


def _genesys_get_access_token(region: str, client_id: str, client_secret: str) -> dict:
  clean_client_id = (client_id or "").strip()
  clean_client_secret = (client_secret or "").strip()
  if not clean_client_id or not clean_client_secret:
    return {"ok": False, "error": "Genesys OAuth client ID and secret are required."}

  clean_region, login_base, _ = _genesys_region_to_urls(region)
  token_url = f"{login_base}/oauth/token"

  try:
    response = requests.post(
      token_url,
      data={"grant_type": "client_credentials"},
      auth=(clean_client_id, clean_client_secret),
      timeout=20,
    )
    payload = response.json() if response.text else {}
  except Exception as exc:
    return {"ok": False, "error": f"Genesys token request failed: {exc}"}

  if response.status_code != 200:
    message = str(payload.get("error_description", "") or payload.get("error", "")).strip() or f"HTTP {response.status_code}"
    return {"ok": False, "error": f"Genesys token request failed: {message}"}

  token = str(payload.get("access_token", "") or "").strip()
  if not token:
    return {"ok": False, "error": "Genesys token response did not include an access token."}

  return {
    "ok": True,
    "region": clean_region,
    "access_token": token,
  }


def _genesys_search_users_by_name(
  region: str,
  access_token: str,
  last_name: str,
  first_name: str = "",
  email_targets: set[str] | None = None,
) -> dict:
  clean_last = (last_name or "").strip().lower()
  clean_first = (first_name or "").strip().lower()
  clean_email_targets = {
    (item or "").strip().lower()
    for item in (email_targets or set())
    if (item or "").strip()
  }
  if not clean_last:
    return {"ok": False, "error": "Last name is required."}

  clean_region, _, api_base = _genesys_region_to_urls(region)
  users_url = f"{api_base}/api/v2/users"
  page_size = max(25, min(GENESYS_USERS_PAGE_SIZE, 200))
  headers = {"Authorization": f"Bearer {access_token}"}

  rows = []
  page_number = 1
  while True:
    try:
      response = requests.get(
        users_url,
        params={
          "pageSize": page_size,
          "pageNumber": page_number,
        },
        headers=headers,
        timeout=25,
      )
      payload = response.json() if response.text else {}
    except Exception as exc:
      return {"ok": False, "error": f"Genesys user lookup failed: {exc}"}

    if response.status_code != 200:
      message = str(payload.get("message", "") or payload.get("error", "")).strip() or f"HTTP {response.status_code}"
      return {"ok": False, "error": f"Genesys user lookup failed: {message}"}

    entities = payload.get("entities", []) or []
    for user in entities:
      name = str(user.get("name", "") or "").strip()
      email = str(user.get("email", "") or "").strip()
      username = str(user.get("username", "") or "").strip()
      haystack = " ".join([name.lower(), email.lower(), username.lower()])
      email_match = bool(email and email.lower() in clean_email_targets)
      name_match = clean_last in haystack and ((not clean_first) or (clean_first in haystack))
      if not (email_match or name_match):
        continue

      rows.append({
        "id": str(user.get("id", "") or "").strip(),
        "name": name,
        "email": email,
        "username": username,
        "state": str(user.get("state", "") or "").strip(),
      })

    page_count = int(payload.get("pageCount", 0) or 0)
    if not page_count or page_number >= page_count:
      break
    page_number += 1

  rows.sort(key=lambda item: ((item.get("name") or "").lower(), (item.get("email") or "").lower()))
  return {
    "ok": True,
    "region": clean_region,
    "rows": rows,
  }


def _genesys_get_json(api_base: str, access_token: str, path: str, params: dict | None = None) -> tuple[bool, dict, str]:
  headers = {"Authorization": f"Bearer {access_token}"}
  url = f"{api_base}{path}"
  try:
    response = requests.get(url, headers=headers, params=params, timeout=25)
    payload = response.json() if response.text else {}
  except Exception as exc:
    return False, {}, f"Genesys API request failed for {path}: {exc}"

  if response.status_code != 200:
    message = str(payload.get("message", "") or payload.get("error", "")).strip() or f"HTTP {response.status_code}"
    return False, payload if isinstance(payload, dict) else {}, message
  return True, payload if isinstance(payload, dict) else {}, ""


def _genesys_send_json(
  method: str,
  api_base: str,
  access_token: str,
  path: str,
  payload: dict | None = None,
  params: dict | None = None,
) -> tuple[bool, dict, str, int]:
  headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json",
  }
  url = f"{api_base}{path}"
  try:
    response = requests.request(
      method=method.upper(),
      url=url,
      headers=headers,
      params=params,
      json=payload or {},
      timeout=30,
    )
    body = response.json() if response.text else {}
  except Exception as exc:
    return False, {}, f"Genesys API request failed for {path}: {exc}", 0

  success_codes = {200, 201, 202, 204}
  if response.status_code not in success_codes:
    message = str(body.get("message", "") or body.get("error", "")).strip() or f"HTTP {response.status_code}"
    return False, body if isinstance(body, dict) else {}, message, response.status_code

  return True, body if isinstance(body, dict) else {}, "", response.status_code


def _genesys_build_webrtc_phone_for_user(region: str, access_token: str, user_id: str, user_name: str) -> dict:
  clean_region, _, api_base = _genesys_region_to_urls(region)
  fallback_template = _load_genesys_webrtc_template()

  site_id = str(fallback_template.get("site_id", "") or "").strip()
  base_settings_id = str(fallback_template.get("phone_base_settings_id", "") or "").strip()
  standalone = bool(fallback_template.get("standalone", False))
  display_name = str(user_name or "").strip() or f"WebRTC-{user_id[:8]}"

  if not site_id or not base_settings_id:
    return {
      "ok": False,
      "error": "WebRTC template is missing site_id or phone_base_settings_id.",
      "region": clean_region,
    }

  base_payload = {
    "name": display_name,
    "site": {"id": site_id},
    "phoneBaseSettings": {"id": base_settings_id},
    "standAlone": standalone,
  }

  attempts = [
    ("webRtcUser", {**base_payload, "webRtcUser": {"id": user_id}}),
    ("user", {**base_payload, "user": {"id": user_id}}),
    ("base", base_payload),
  ]

  created_phone = {}
  create_mode = ""
  create_errors = []
  for mode_name, payload in attempts:
    ok_create, create_body, create_err, _ = _genesys_send_json(
      "POST",
      api_base,
      access_token,
      "/api/v2/telephony/providers/edges/phones",
      payload,
    )
    if ok_create:
      created_phone = create_body if isinstance(create_body, dict) else {}
      create_mode = mode_name
      break
    create_errors.append(f"{mode_name}: {create_err}")

  if not created_phone:
    return {
      "ok": False,
      "error": " | ".join(create_errors) if create_errors else "Phone creation failed.",
      "region": clean_region,
    }

  created_phone_id = str(created_phone.get("id", "") or "").strip()
  created_phone_name = str(created_phone.get("name", "") or display_name).strip()

  association_result = "Created"
  if create_mode == "base" and created_phone_id:
    ok_assoc, _, assoc_err, assoc_status = _genesys_send_json(
      "POST",
      api_base,
      access_token,
      f"/api/v2/users/{user_id}/stationassociations",
      {"station": {"id": created_phone_id}},
    )
    if ok_assoc:
      association_result = "Created+Associated"
    else:
      association_result = f"Created (association pending: {assoc_status} {assoc_err})"

  return {
    "ok": True,
    "region": clean_region,
    "phone_id": created_phone_id,
    "phone_name": created_phone_name,
    "create_mode": create_mode,
    "association_result": association_result,
  }


def _genesys_extract_webrtc_phone(user_payload: dict, routing_payload: dict, station_associations_payload: dict | None = None) -> str:
  station = routing_payload.get("station") if isinstance(routing_payload, dict) else {}
  if isinstance(station, dict):
    station_name = str(station.get("name", "") or "").strip()
    if station_name:
      return station_name

  # Fall back to user profile station field.
  user_station = user_payload.get("station") if isinstance(user_payload, dict) else {}
  if isinstance(user_station, dict):
    user_station_name = str(user_station.get("name", "") or "").strip()
    if user_station_name:
      return user_station_name

  # Final fallback: use the station association list for the user.
  payload = station_associations_payload if isinstance(station_associations_payload, dict) else {}
  entities = payload.get("entities", []) or []
  for item in entities:
    if not isinstance(item, dict):
      continue
    station_obj = item.get("station") if isinstance(item.get("station"), dict) else item
    station_name = str(station_obj.get("name", "") or "").strip()
    if station_name:
      return station_name
    station_id = str(station_obj.get("id", "") or "").strip()
    if station_id:
      return station_id

  return ""


def _genesys_extract_phone_management_name(phone_payload: dict, user_id: str, user_name: str, user_email: str) -> tuple[str, dict]:
  entities = phone_payload.get("entities", []) if isinstance(phone_payload, dict) else []
  clean_user_id = str(user_id or "").strip().lower()
  clean_user_name = str(user_name or "").strip().lower()
  clean_user_email = str(user_email or "").strip().lower()

  def _normalized(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())

  for item in entities or []:
    if not isinstance(item, dict):
      continue

    # Collect candidate fields that might reference the owning user.
    owner_tokens = []
    for key in ["user", "owner", "webRtcUser", "associatedUser", "primaryUser", "effectiveOwner"]:
      obj = item.get(key)
      if isinstance(obj, dict):
        owner_tokens.append(str(obj.get("id", "") or "").strip().lower())
        owner_tokens.append(str(obj.get("name", "") or "").strip().lower())
        owner_tokens.append(str(obj.get("email", "") or "").strip().lower())

    for key in ["userId", "ownerUserId", "ownerId", "associatedUserId", "username", "email"]:
      owner_tokens.append(str(item.get(key, "") or "").strip().lower())

    owner_tokens = [token for token in owner_tokens if token]

    phone_name_candidates = []
    for key in ["name", "displayName", "stationName", "phoneName"]:
      candidate = str(item.get(key, "") or "").strip()
      if candidate:
        phone_name_candidates.append(candidate)

    normalized_phone_names = [_normalized(value) for value in phone_name_candidates if value]
    normalized_user_name = _normalized(clean_user_name)

    is_match = False
    if clean_user_id and clean_user_id in owner_tokens:
      is_match = True
    elif clean_user_email and clean_user_email in owner_tokens:
      is_match = True
    elif clean_user_name and any(clean_user_name in token for token in owner_tokens if token):
      is_match = True
    elif (not owner_tokens) and normalized_user_name and any(pn == normalized_user_name for pn in normalized_phone_names if pn):
      # Some orgs return phones without owner linkage; use exact-name fallback.
      is_match = True

    if not is_match:
      continue

    for key in ["name", "phoneName", "stationName", "displayName"]:
      value = str(item.get(key, "") or "").strip()
      if value:
        return value, item

    item_id = str(item.get("id", "") or "").strip()
    if item_id:
      return item_id, item

  return "", {}


def _genesys_lookup_phone_management_name(api_base: str, access_token: str, user_id: str, user_name: str, user_email: str) -> tuple[str, dict, dict, str]:
  # Phone inventory can be large; allow a configurable cap to avoid missing users.
  merged_entities = []
  max_pages = max(1, min(GENESYS_PHONE_LOOKUP_MAX_PAGES, 200))
  for page_number in range(1, max_pages + 1):
    ok_phones, phones_payload, err_phones = _genesys_get_json(
      api_base,
      access_token,
      "/api/v2/telephony/providers/edges/phones",
      params={"pageSize": 100, "pageNumber": page_number},
    )
    if not ok_phones:
      return "", {}, {}, err_phones

    entities = phones_payload.get("entities", []) if isinstance(phones_payload, dict) else []
    if isinstance(entities, list):
      merged_entities.extend(entities)

    page_count = int(phones_payload.get("pageCount", 0) or 0) if isinstance(phones_payload, dict) else 0
    if not page_count or page_number >= page_count:
      break

  payload = {"entities": merged_entities}
  phone_name, matched_phone = _genesys_extract_phone_management_name(payload, user_id, user_name, user_email)
  return phone_name, matched_phone, payload, ""


def _genesys_queue_member_matches_user(member: dict, user_id: str, user_email: str, user_name: str) -> bool:
  if not isinstance(member, dict):
    return False

  clean_user_id = str(user_id or "").strip().lower()
  clean_user_email = str(user_email or "").strip().lower()
  clean_user_name = str(user_name or "").strip().lower()

  candidates = []
  for key in ["id", "userId", "memberId", "email", "username", "name"]:
    value = str(member.get(key, "") or "").strip().lower()
    if value:
      candidates.append(value)

  user_obj = member.get("user") if isinstance(member.get("user"), dict) else {}
  for key in ["id", "email", "username", "name"]:
    value = str(user_obj.get(key, "") or "").strip().lower()
    if value:
      candidates.append(value)

  if clean_user_id and clean_user_id in candidates:
    return True
  if clean_user_email and clean_user_email in candidates:
    return True
  if clean_user_name and any(clean_user_name == item for item in candidates):
    return True
  return False


def _genesys_get_queue_name(api_base: str, access_token: str, queue_id: str) -> str:
  clean_queue_id = str(queue_id or "").strip()
  if not clean_queue_id:
    return ""

  ok_queue, queue_payload, _ = _genesys_get_json(api_base, access_token, f"/api/v2/routing/queues/{clean_queue_id}")
  if ok_queue and isinstance(queue_payload, dict):
    queue_name = str(queue_payload.get("name", "") or "").strip()
    if queue_name:
      return queue_name
  return clean_queue_id


def _genesys_lookup_user_queues_by_ids(api_base: str, access_token: str, user_id: str, user_email: str, user_name: str, queue_ids: list[str]) -> list[str]:
  matched_queue_names = []

  for queue_id in queue_ids:
    clean_queue_id = str(queue_id or "").strip()
    if not clean_queue_id:
      continue

    members, _ = _genesys_get_queue_members(api_base, access_token, clean_queue_id)
    found_in_queue = any(
      _genesys_queue_member_matches_user(member, user_id, user_email, user_name)
      for member in members
      if isinstance(member, dict)
    )

    if found_in_queue:
      matched_queue_names.append(_genesys_get_queue_name(api_base, access_token, clean_queue_id))

  return sorted(set(matched_queue_names), key=str.lower)


def _genesys_lookup_user_queues_via_membership(api_base: str, access_token: str, user_id: str, user_email: str, user_name: str) -> tuple[list[str], str]:
  # First, check known priority queue IDs when provided.
  if GENESYS_PRIORITY_QUEUE_IDS:
    priority_matches = _genesys_lookup_user_queues_by_ids(
      api_base,
      access_token,
      user_id,
      user_email,
      user_name,
      GENESYS_PRIORITY_QUEUE_IDS,
    )
    if priority_matches:
      return priority_matches, ""

  queue_entities = []
  max_queue_pages = max(1, min(GENESYS_QUEUE_LOOKUP_MAX_PAGES, 200))

  for page_number in range(1, max_queue_pages + 1):
    ok_queues, queues_payload, err_queues = _genesys_get_json(
      api_base,
      access_token,
      "/api/v2/routing/queues",
      params={"pageSize": 100, "pageNumber": page_number},
    )
    if not ok_queues:
      return [], err_queues

    entities = queues_payload.get("entities", []) if isinstance(queues_payload, dict) else []
    if isinstance(entities, list):
      queue_entities.extend(entities)

    page_count = int(queues_payload.get("pageCount", 0) or 0) if isinstance(queues_payload, dict) else 0
    if not page_count or page_number >= page_count:
      break

  matched_queue_names = []
  for queue_item in queue_entities:
    if not isinstance(queue_item, dict):
      continue

    queue_id = str(queue_item.get("id", "") or "").strip()
    queue_name = str(queue_item.get("name", "") or "").strip()
    if not queue_id:
      continue

    members, _ = _genesys_get_queue_members(api_base, access_token, queue_id)
    found_in_queue = any(
      _genesys_queue_member_matches_user(member, user_id, user_email, user_name)
      for member in members
      if isinstance(member, dict)
    )

    if found_in_queue and queue_name:
      matched_queue_names.append(queue_name)

  return sorted(set(matched_queue_names), key=str.lower), ""


def _genesys_search_queues_by_name(api_base: str, access_token: str, queue_name: str) -> tuple[list[dict], str]:
  clean_queue_name = str(queue_name or "").strip().lower()
  if not clean_queue_name:
    return [], "Queue name is required."

  matched = []
  max_queue_pages = max(1, min(GENESYS_QUEUE_LOOKUP_MAX_PAGES, 200))
  for page_number in range(1, max_queue_pages + 1):
    ok_queues, queues_payload, err_queues = _genesys_get_json(
      api_base,
      access_token,
      "/api/v2/routing/queues",
      params={"pageSize": 100, "pageNumber": page_number},
    )
    if not ok_queues:
      return [], err_queues

    entities = queues_payload.get("entities", []) if isinstance(queues_payload, dict) else []
    for item in entities:
      if not isinstance(item, dict):
        continue
      q_name = str(item.get("name", "") or "").strip()
      q_id = str(item.get("id", "") or "").strip()
      if not q_name and not q_id:
        continue

      q_name_l = q_name.lower()
      q_id_l = q_id.lower()
      if clean_queue_name == q_name_l or clean_queue_name == q_id_l or clean_queue_name in q_name_l:
        matched.append(item)

    page_count = int(queues_payload.get("pageCount", 0) or 0) if isinstance(queues_payload, dict) else 0
    if not page_count or page_number >= page_count:
      break

  # Prefer exact name/id matches first.
  def _rank(item: dict) -> tuple[int, str]:
    q_name = str(item.get("name", "") or "").strip().lower()
    q_id = str(item.get("id", "") or "").strip().lower()
    if clean_queue_name == q_name or clean_queue_name == q_id:
      return (0, q_name)
    return (1, q_name)

  return sorted(matched, key=_rank), ""


def _genesys_get_queue_members(api_base: str, access_token: str, queue_id: str) -> tuple[list[dict], str]:
  members, _, err = _genesys_get_queue_members_with_diagnostics(api_base, access_token, queue_id)
  return members, err


def _genesys_extract_queue_id_hint(queue_query: str) -> str:
  clean_query = str(queue_query or "").strip()
  if not clean_query:
    return ""

  match = GENESYS_QUEUE_ID_PATTERN.search(clean_query)
  return match.group(0).lower() if match else ""


def _genesys_get_queue_members_with_diagnostics(api_base: str, access_token: str, queue_id: str) -> tuple[list[dict], list[str], str]:
  clean_queue_id = str(queue_id or "").strip()
  if not clean_queue_id:
    return [], [], "Queue id is required."

  diagnostics = []
  errors = []
  fallback_variants = [
    {
      "label": "members",
      "path": f"/api/v2/routing/queues/{clean_queue_id}/members",
      "params": {"pageSize": 100},
      "wrap_user": False,
    },
    {
      "label": "members-expand-user",
      "path": f"/api/v2/routing/queues/{clean_queue_id}/members",
      "params": {"pageSize": 100, "expand": "user"},
      "wrap_user": False,
    },
    {
      "label": "users",
      "path": f"/api/v2/routing/queues/{clean_queue_id}/users",
      "params": {"pageSize": 100},
      "wrap_user": True,
    },
  ]

  max_member_pages = max(1, min(GENESYS_QUEUE_MEMBER_MAX_PAGES, 200))
  for variant in fallback_variants:
    collected = []
    strategy = str(variant.get("label", "")).strip() or "members"
    path = str(variant.get("path", "")).strip()
    base_params = dict(variant.get("params", {}) or {})
    wrap_user = bool(variant.get("wrap_user", False))

    for member_page in range(1, max_member_pages + 1):
      request_params = dict(base_params)
      request_params["pageNumber"] = member_page
      ok_members, members_payload, err_members = _genesys_get_json(
        api_base,
        access_token,
        path,
        params=request_params,
      )
      if not ok_members:
        errors.append(f"{strategy}: {err_members}")
        diagnostics.append(f"{strategy} page {member_page}: failed ({err_members})")
        break

      entities = members_payload.get("entities", []) if isinstance(members_payload, dict) else []
      page_items = 0
      for item in entities:
        if not isinstance(item, dict):
          continue
        page_items += 1
        if wrap_user:
          collected.append({"user": item, "id": item.get("id", "")})
        else:
          collected.append(item)

      page_count = int(members_payload.get("pageCount", 0) or 0) if isinstance(members_payload, dict) else 0
      diagnostics.append(f"{strategy} page {member_page}: {page_items} item(s)")
      if not page_count or member_page >= page_count:
        break

    if collected:
      unique = []
      seen = set()
      for member in collected:
        user_obj = member.get("user") if isinstance(member.get("user"), dict) else {}
        member_key = "|".join([
          str(user_obj.get("id", "") or member.get("id", "") or "").strip().lower(),
          str(user_obj.get("email", "") or member.get("email", "") or "").strip().lower(),
          str(user_obj.get("name", "") or member.get("name", "") or "").strip().lower(),
        ])
        if member_key in seen:
          continue
        seen.add(member_key)
        unique.append(member)
      diagnostics.append(f"selected strategy: {strategy} ({len(unique)} unique member(s))")
      return unique, diagnostics, ""

  if errors:
    return [], diagnostics, errors[0]
  return [], diagnostics, ""


def _load_genesys_webrtc_template() -> dict:
  try:
    with open(GENESYS_WEBRTC_TEMPLATE_PATH, "r", encoding="utf-8") as handle:
      payload = json.load(handle)
      if isinstance(payload, dict):
        return payload
  except Exception:
    pass

  return {
    "template_name": "Default WebRTC Template",
    "source_phone_name": "Michael Beecher",
    "site_id": "",
    "phone_base_settings_id": "",
    "standalone": False,
    "line_count": 0,
  }


def _build_phone_template_summary(phone_entity: dict, fallback_template: dict) -> dict:
  template_name = str(fallback_template.get("template_name", "") or "").strip()
  source_phone_name = str(fallback_template.get("source_phone_name", "") or "").strip()
  site_id = str(fallback_template.get("site_id", "") or "").strip()
  phone_base_settings_id = str(fallback_template.get("phone_base_settings_id", "") or "").strip()
  standalone = bool(fallback_template.get("standalone", False))
  line_count = int(fallback_template.get("line_count", 0) or 0)
  source = "template-file"

  if isinstance(phone_entity, dict) and phone_entity:
    source = "matched-phone"
    template_name = str(phone_entity.get("name", "") or template_name).strip()
    source_phone_name = str(phone_entity.get("name", "") or source_phone_name).strip()
    site_obj = phone_entity.get("site") if isinstance(phone_entity.get("site"), dict) else {}
    pbs_obj = phone_entity.get("phoneBaseSettings") if isinstance(phone_entity.get("phoneBaseSettings"), dict) else {}
    lines_obj = phone_entity.get("lines") if isinstance(phone_entity.get("lines"), list) else []
    site_id = str(site_obj.get("id", "") or site_id).strip()
    phone_base_settings_id = str(pbs_obj.get("id", "") or phone_base_settings_id).strip()
    standalone = bool(phone_entity.get("standAlone", standalone))
    line_count = len(lines_obj) if lines_obj else line_count

  return {
    "source": source,
    "template_name": template_name,
    "source_phone_name": source_phone_name,
    "site_id": site_id,
    "phone_base_settings_id": phone_base_settings_id,
    "standalone": standalone,
    "line_count": line_count,
  }


def _genesys_enrich_user_rows(region: str, access_token: str, rows: list[dict]) -> dict:
  clean_region, _, api_base = _genesys_region_to_urls(region)
  fallback_template = _load_genesys_webrtc_template()
  enriched = []
  warnings = []
  raw_items = []

  for row in rows:
    user_id = str(row.get("id", "") or "").strip()
    division_name = ""
    webrtc_phone = ""
    phone_template = _build_phone_template_summary({}, fallback_template)
    acd_skills_text = ""
    queues_text = ""
    queue_resolution_source = "none"

    if user_id:
      user_payload = {}
      routing_payload = {}
      skills_payload = {}
      queues_payload = {}
      station_associations_payload = {}
      phone_management_payload = {}
      phone_management_match = {}

      ok_user, user_payload, err_user = _genesys_get_json(api_base, access_token, f"/api/v2/users/{user_id}")
      if ok_user:
        division = user_payload.get("division") or {}
        if isinstance(division, dict):
          division_name = str(division.get("name", "") or "").strip()
      elif err_user:
        warnings.append(f"{row.get('name', user_id)} user profile: {err_user}")

      ok_routing, routing_payload, err_routing = _genesys_get_json(api_base, access_token, f"/api/v2/users/{user_id}/routingstatus")
      if not ok_routing and err_routing:
        warnings.append(f"{row.get('name', user_id)} routing status: {err_routing}")

      ok_station_assoc, station_associations_payload, err_station_assoc = _genesys_get_json(
        api_base,
        access_token,
        f"/api/v2/users/{user_id}/stationassociations",
      )
      if not ok_station_assoc and err_station_assoc:
        warnings.append(f"{row.get('name', user_id)} station associations: {err_station_assoc}")

      webrtc_phone = _genesys_extract_webrtc_phone(
        user_payload if ok_user else {},
        routing_payload if ok_routing else {},
        station_associations_payload if ok_station_assoc else {},
      )

      phone_management_name, phone_management_match, phone_management_payload, err_phone_mgmt = _genesys_lookup_phone_management_name(
        api_base,
        access_token,
        user_id,
        str(row.get("name", "") or ""),
        str(row.get("email", "") or ""),
      )
      if phone_management_name and not webrtc_phone:
        webrtc_phone = phone_management_name
      if err_phone_mgmt:
        warnings.append(f"{row.get('name', user_id)} phone management lookup: {err_phone_mgmt}")

      phone_template = _build_phone_template_summary(phone_management_match, fallback_template)

      ok_skills, skills_payload, err_skills = _genesys_get_json(api_base, access_token, f"/api/v2/users/{user_id}/routingskills")
      if ok_skills:
        entities = skills_payload.get("entities", []) or []
        names = []
        for item in entities:
          if not isinstance(item, dict):
            continue

          # Genesys payloads can provide the skill name either directly on the entity
          # or nested under `skill.name` depending on endpoint/version.
          skill_name = str(item.get("name", "") or "").strip()
          if not skill_name:
            skill = item.get("skill") if isinstance(item.get("skill"), dict) else {}
            skill_name = str(skill.get("name", "") or "").strip()
          if skill_name:
            names.append(skill_name)
        acd_skills_text = ", ".join(sorted(set(names), key=str.lower)) if names else "(none)"
      elif err_skills:
        warnings.append(f"{row.get('name', user_id)} skills: {err_skills}")

      ok_queues, queues_payload, err_queues = _genesys_get_json(api_base, access_token, f"/api/v2/users/{user_id}/queues")
      if ok_queues:
        entities = queues_payload.get("entities", []) or []
        queue_names = []
        for item in entities:
          q_name = str(item.get("name", "") or "").strip() if isinstance(item, dict) else ""
          if q_name:
            queue_names.append(q_name)
        if queue_names:
          queues_text = ", ".join(sorted(set(queue_names), key=str.lower))
          queue_resolution_source = "direct-user-queues"
        else:
          fallback_queue_names, fallback_queue_err = _genesys_lookup_user_queues_via_membership(
            api_base,
            access_token,
            user_id,
            str(row.get("email", "") or ""),
            str(row.get("name", "") or ""),
          )
          if fallback_queue_names:
            queues_text = ", ".join(fallback_queue_names)
            queue_resolution_source = "membership-fallback"
          else:
            queues_text = "(none)"
            queue_resolution_source = "none"
            if fallback_queue_err:
              warnings.append(f"{row.get('name', user_id)} queue membership fallback: {fallback_queue_err}")
      elif err_queues:
        warnings.append(f"{row.get('name', user_id)} queues: {err_queues}")

      raw_items.append({
        "user_id": user_id,
        "name": str(row.get("name", "") or "").strip(),
        "email": str(row.get("email", "") or "").strip(),
        "user": user_payload if ok_user else {},
        "routing_status": routing_payload if ok_routing else {},
        "station_associations": station_associations_payload if ok_station_assoc else {},
        "phone_management_match": phone_management_match,
        "phone_template": phone_template,
        "phone_management": phone_management_payload,
        "routing_skills": skills_payload if ok_skills else {},
        "queues": queues_payload if ok_queues else {},
        "resolved_queues": queues_text,
        "queue_resolution_source": queue_resolution_source,
      })

    merged = dict(row)
    merged["division"] = division_name
    merged["webrtc_phone"] = webrtc_phone
    merged["phone_template_source"] = str(phone_template.get("source", "") or "")
    merged["phone_template_name"] = str(phone_template.get("template_name", "") or "")
    merged["phone_template_site_id"] = str(phone_template.get("site_id", "") or "")
    merged["phone_template_base_settings_id"] = str(phone_template.get("phone_base_settings_id", "") or "")
    merged["phone_template_line_count"] = int(phone_template.get("line_count", 0) or 0)
    merged["has_webrtc_phone"] = bool(str(webrtc_phone or "").strip())
    merged["can_build_webrtc"] = not bool(str(webrtc_phone or "").strip())
    merged["acd_skills"] = acd_skills_text
    merged["queues"] = queues_text
    enriched.append(merged)

  return {
    "ok": True,
    "region": clean_region,
    "rows": enriched,
    "warnings": warnings,
    "raw_items": raw_items,
  }


def _create_auth_session(cucm_host: str, username: str, cucm_pass: str) -> str:
  session_id = str(uuid4())
  now_epoch = time.time()
  AUTH_SESSIONS[session_id] = {
    "cucm_host": (cucm_host or "").strip(),
    "username": (username or "").strip(),
    "cucm_user": (username or "").strip(),
    "unity_user": (username or "").strip(),
    "created_at": now_epoch,
    "last_seen": now_epoch,
    "credential_expires_at": now_epoch + CREDENTIAL_CACHE_TTL_SECONDS,
  }
  AUTH_SESSION_SECRETS[session_id] = {
    "cucm_pass": (cucm_pass or "").strip(),
    "unity_pass": "",
  }
  _cache_secret(AUTH_SESSIONS[session_id], "cucm_pass", cucm_pass, now_epoch)
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

  if now_epoch > float(session.get("credential_expires_at", 0) or 0):
    AUTH_SESSIONS.pop(session_id, None)
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
  cucm_pass: str = "",
  unity_user: str = "",
  unity_pass: str = "",
):
  session = _get_auth_session(request)
  if not session:
    return

  session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
  secret_store = AUTH_SESSION_SECRETS.setdefault(session_id, {}) if session_id else None

  if (cucm_host or "").strip():
    session["cucm_host"] = cucm_host.strip()
  if (cucm_user or "").strip():
    session["cucm_user"] = cucm_user.strip()
  if (cucm_pass or "").strip():
    _cache_secret(session, "cucm_pass", cucm_pass)
    if secret_store is not None:
      secret_store["cucm_pass"] = (cucm_pass or "").strip()
  if (unity_user or "").strip():
    session["unity_user"] = unity_user.strip()
  if (unity_pass or "").strip():
    _cache_secret(session, "unity_pass", unity_pass)
    if secret_store is not None:
      secret_store["unity_pass"] = (unity_pass or "").strip()


def _load_settings():
  """Load DN prefix settings from settings.json, or return defaults if not found."""
  try:
    if os.path.exists(SETTINGS_FILE_PATH):
      with open(SETTINGS_FILE_PATH, "r") as f:
        settings = json.load(f)
        # Merge with defaults to ensure all keys exist
        return {**DEFAULT_SETTINGS, **settings}
  except Exception:
    pass
  return DEFAULT_SETTINGS.copy()


def _save_settings(settings: dict):
  """Save DN prefix settings to settings.json."""
  try:
    with SETTINGS_LOCK:
      os.makedirs(os.path.dirname(SETTINGS_FILE_PATH), exist_ok=True)
      with open(SETTINGS_FILE_PATH, "w") as f:
        json.dump(settings, f, indent=2)
      return True
  except Exception as e:
    print(f"Error saving settings: {e}")
    return False


def _get_dn_mapping():
  """Get the current DN prefix mapping from settings."""
  settings = _load_settings()
  return {
    "recruiter": (settings.get("recruiter_prefix", "469"), "Recruiter"),
    "general": (settings.get("general_fte_prefix", "945"), "General FTE"),
    "strike": (settings.get("strike_prefix", "817"), "Strike"),
  }


def _get_sep_report_settings() -> dict:
  """Return live separation report settings, preferring settings.json over .env constants."""
  s = _load_settings()

  def _str(key, fallback):
    v = (s.get(key) or "").strip()
    return v if v else fallback

  def _int(key, fallback):
    v = (s.get(key) or "").strip()
    try:
      return int(v) if v else fallback
    except ValueError:
      return fallback

  enabled_raw = (s.get("sep_report_enabled") or "").strip().lower()
  enabled = (SEPARATION_REPORT_ENABLED if not enabled_raw else enabled_raw in {"1", "true", "yes", "on"})

  return {
    "enabled": enabled,
    "recipient": _str("sep_report_recipient", SEPARATION_REPORT_RECIPIENT),
    "recipient_2": _str("sep_report_recipient_2", SEPARATION_REPORT_RECIPIENT_2),
    "from_address": _str("sep_report_from", SEPARATION_REPORT_FROM),
    "hour": _int("sep_report_hour", SEPARATION_REPORT_HOUR),
    "minute": _int("sep_report_minute", SEPARATION_REPORT_MINUTE),
    "frequency": _str("sep_report_frequency", SEPARATION_REPORT_FREQUENCY),
    "weekly_day": _str("sep_report_weekly_day", SEPARATION_REPORT_WEEKLY_DAY),
  }


def _get_dn_report_settings() -> dict:
  """Return live DN availability report settings from settings.json with env/constant fallbacks."""
  s = _load_settings()

  def _str(key, fallback=""):
    v = (s.get(key) or "").strip()
    return v if v else fallback

  def _int(key, fallback):
    v = (s.get(key) or "").strip()
    try:
      return int(v) if v else fallback
    except ValueError:
      return fallback

  enabled_raw = (s.get("dn_report_enabled") or "").strip().lower()
  enabled = True if not enabled_raw else enabled_raw in {"1", "true", "yes", "on"}

  return {
    "enabled": enabled,
    "recipient": _str("dn_report_recipient"),
    "recipient_2": _str("dn_report_recipient_2"),
    "from_address": _str("dn_report_from", "noreply@amnhealthcare.com"),
    "hour": _int("dn_report_hour", 8),
    "minute": _int("dn_report_minute", 0),
    "frequency": _str("dn_report_frequency", "daily"),
    "cucm_host": _str("dn_report_cucm_host", PROD_CUCM_HOST),
    "cucm_user": _str("dn_report_cucm_user", "ucmappadmin"),
    "cucm_pass": _str("dn_report_cucm_pass", "abi3rto!"),
    "low_threshold": _int("dn_report_low_threshold", 10),
  }


def _resolve_cucm_credentials(request: Request, cucm_host: str, cucm_user: str, cucm_pass: str):
  session = _get_auth_session(request)
  if not session:
    raise RuntimeError("Authentication required.")

  resolved_host = (cucm_host or "").strip() or session.get("cucm_host", "")
  provided_user = (cucm_user or "").strip()
  if provided_user:
    session["cucm_user"] = provided_user
  resolved_user = provided_user or session.get("cucm_user", "") or session.get("username", "")
  provided_pass = (cucm_pass or "").strip()
  session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
  secret_store = AUTH_SESSION_SECRETS.get(session_id, {}) if session_id else {}
  if provided_pass:
    _cache_secret(session, "cucm_pass", provided_pass)
    if session_id:
      secret_store = AUTH_SESSION_SECRETS.setdefault(session_id, {})
      secret_store["cucm_pass"] = provided_pass
  resolved_pass = provided_pass or _get_cached_secret(session, "cucm_pass")
  if not resolved_pass:
    resolved_pass = (secret_store.get("cucm_pass", "") or "").strip()
  if not resolved_pass:
    # Final fallback for sessions that still carry plain value from compatibility path.
    resolved_pass = (session.get("cucm_pass", "") or "").strip()
    if resolved_pass:
      _cache_secret(session, "cucm_pass", resolved_pass)

  if not resolved_host or not resolved_user or not resolved_pass:
    raise RuntimeError("Session credentials expired. Please log in again.")

  return resolved_host, resolved_user, resolved_pass


def _resolve_unity_credentials(request: Request, unity_user: str, unity_pass: str):
  session = _get_auth_session(request)
  if not session:
    raise RuntimeError("Authentication required.")

  resolved_user = (unity_user or "").strip() or session.get("unity_user", "") or session.get("username", "")
  provided_pass = (unity_pass or "").strip()
  session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
  secret_store = AUTH_SESSION_SECRETS.get(session_id, {}) if session_id else {}
  if provided_pass:
    _cache_secret(session, "unity_pass", provided_pass)
    if session_id:
      secret_store = AUTH_SESSION_SECRETS.setdefault(session_id, {})
      secret_store["unity_pass"] = provided_pass
  resolved_pass = provided_pass or _get_cached_secret(session, "unity_pass") or _get_cached_secret(session, "cucm_pass")
  if not resolved_pass:
    resolved_pass = (secret_store.get("unity_pass", "") or "").strip() or (secret_store.get("cucm_pass", "") or "").strip()

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


def _trigger_cucm_ldap_sync(cucm_host: str, cucm_user: str, cucm_pass: str, agreement_name: str):
  soap_xml = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:doLdapSync>
      <name>{xml_escape(agreement_name)}</name>
      <sync>true</sync>
    </axl:doLdapSync>
  </soapenv:Body>
</soapenv:Envelope>"""

  url = f"https://{cucm_host}:8443/axl/"
  response = requests.post(
    url,
    data=soap_xml.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    auth=HTTPBasicAuth(cucm_user, cucm_pass),
    timeout=60,
    verify=False,
  )

  if response.status_code == 200:
    return True, f"LDAP sync triggered for agreement '{agreement_name}'."

  error_text = _extract_soap_error(response.text or "")
  if not error_text:
    error_text = f"HTTP {response.status_code}"
  return False, f"LDAP sync failed for agreement '{agreement_name}': {error_text}"


def _trigger_unity_ldap_sync(unity_server: str, unity_user: str, unity_pass: str):
  unity_base = (unity_server or "").strip()
  if not unity_base:
    raise RuntimeError("Unity server is missing.")

  if not unity_base.startswith("http://") and not unity_base.startswith("https://"):
    unity_base = f"https://{unity_base}"

  url = f"{unity_base.rstrip('/')}/vmrest/import/users/ldap"
  headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
  }

  # Unity does not expose AXL-like doLdapSync; this call requests the LDAP import endpoint,
  # which refreshes/validates import availability for the current Unity environment.
  attempts = [
    ({"query": "(alias startswith a)", "rowsPerPage": "1", "synchronize": "true"}, "synchronize=true"),
    ({"query": "(alias startswith a)", "rowsPerPage": "1"}, "standard import query"),
  ]

  errors = []
  for params, attempt_label in attempts:
    response = requests.get(
      url,
      headers=headers,
      params=params,
      auth=HTTPBasicAuth(unity_user, unity_pass),
      timeout=60,
      verify=False,
    )

    if response.status_code == 200:
      return True, f"Unity LDAP sync request sent to {unity_server} via {attempt_label}."

    body = (response.text or "").strip()
    if not body:
      body = f"HTTP {response.status_code}"
    errors.append(f"{attempt_label}: {body[:600]}")

  return False, "Unity LDAP sync trigger failed. " + " | ".join(errors)


def _is_lab_host(cucm_host: str):
  return (cucm_host or "").strip().lower() == LAB_CUCM_HOST.lower()


def _get_environment_label(cucm_host: str):
  if _is_lab_host(cucm_host):
    return "LAB Voice Servers - TESTING ONLY", "env-banner-lab"
  return "Production Voice Servers", "env-banner-prod"


def _is_lab_runtime_host():
  host_candidates = {
    (os.getenv("HOSTNAME", "") or "").strip().lower(),
    (os.getenv("COMPUTERNAME", "") or "").strip().lower(),
  }
  try:
    host_candidates.add((socket.gethostname() or "").strip().lower())
  except Exception:
    pass
  try:
    host_candidates.add((socket.getfqdn() or "").strip().lower())
  except Exception:
    pass

  for host in host_candidates:
    if not host:
      continue
    if "lascrtmp01" in host:
      return True
    if "ciscoadminp01" in host:
      return False

  return None


def _is_lab_environment(cucm_host: str = ""):
  runtime_is_lab = _is_lab_runtime_host()
  if runtime_is_lab is not None:
    return runtime_is_lab
  return _is_lab_host(cucm_host)


def _get_runtime_cucm_host(default_host: str = ""):
  runtime_is_lab = _is_lab_runtime_host()
  if runtime_is_lab is True:
    return LAB_CUCM_HOST
  if runtime_is_lab is False:
    return PROD_CUCM_HOST
  return (default_host or "").strip()


def _get_runtime_unity_host(default_host: str = ""):
  runtime_is_lab = _is_lab_runtime_host()
  if runtime_is_lab is True:
    return LAB_UNITY_HOST
  if runtime_is_lab is False:
    return PROD_UNITY_HOST
  return (default_host or "").strip()


def _get_unity_server_for_session(request: Request):
  runtime_is_lab = _is_lab_runtime_host()
  if runtime_is_lab is True:
    return LAB_UNITY_HOST
  if runtime_is_lab is False:
    return PROD_UNITY_HOST

  session = _get_auth_session(request)
  if not session:
    raise RuntimeError("Authentication required.")

  cucm_host = session.get("cucm_host", "")
  if _is_lab_host(cucm_host):
    return LAB_UNITY_HOST
  return PROD_UNITY_HOST


def _feature_enabled(flag_enabled: bool, lab_only: bool = False, cucm_host: str = "") -> bool:
  if not flag_enabled:
    return False
  if not lab_only:
    return True
  return _is_lab_environment(cucm_host)


def _build_lookup_error(service_name: str, reason: str, hint: str = "") -> str:
  safe_service = (service_name or "Lookup service").strip()
  safe_reason = (reason or "Lookup failed").strip()
  safe_hint = (hint or "").strip()
  if safe_hint:
    return f"{safe_service} unavailable: {safe_reason}. Next: {safe_hint}"
  return f"{safe_service} unavailable: {safe_reason}"


def _git_commit_short() -> str:
  repo_dir = os.path.dirname(os.path.abspath(__file__))

  for git_cmd in ["git", "/usr/bin/git"]:
    try:
      commit = subprocess.check_output(
        [git_cmd, "-C", repo_dir, "rev-parse", "--short", "HEAD"],
        text=True,
        stderr=subprocess.DEVNULL,
      ).strip()
      if commit:
        return commit
    except Exception:
      continue

  # Fallback when git is unavailable in PATH for service context.
  try:
    head_path = os.path.join(repo_dir, ".git", "HEAD")
    with open(head_path, "r", encoding="utf-8") as handle:
      head_value = (handle.read() or "").strip()

    if head_value.startswith("ref:"):
      ref_rel = head_value.split(" ", 1)[-1].strip()
      ref_path = os.path.join(repo_dir, ".git", ref_rel.replace("/", os.sep))
      with open(ref_path, "r", encoding="utf-8") as ref_handle:
        full_hash = (ref_handle.read() or "").strip()
      if full_hash:
        return full_hash[:7]

    if head_value:
      return head_value[:7]
  except Exception:
    pass

  try:
    return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=repo_dir, text=True).strip()
  except Exception:
    return "unknown"


def _parse_certificate_not_after(value: str):
  text = (value or "").strip()
  if not text:
    return None

  for fmt in ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"]:
    try:
      dt = datetime.datetime.strptime(text, fmt)
      if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
      return dt.astimezone(datetime.timezone.utc)
    except Exception:
      continue
  return None


def _extract_cert_name(parts) -> str:
  tokens = []
  for part in parts or []:
    for key, value in part:
      if value:
        tokens.append(f"{key}={value}")
  return ", ".join(tokens)


def _html_to_text(value: str) -> str:
  text = value or ""
  text = re.sub(r"<br\s*/?>", " ", text, flags=re.IGNORECASE)
  text = re.sub(r"<[^>]+>", " ", text)
  text = unescape(text)
  return re.sub(r"\s+", " ", text).strip()


def _parse_platform_expiration_date(value: str):
  raw = (value or "").strip()
  if not raw:
    return None

  for fmt in ["%m/%d/%Y", "%m/%d/%y", "%Y-%m-%d"]:
    try:
      return datetime.datetime.strptime(raw, fmt).date()
    except Exception:
      continue
  return None


def _extract_balanced_segment(source: str, start_index: int, opener: str, closer: str) -> str:
  text = source or ""
  if start_index < 0 or start_index >= len(text) or text[start_index] != opener:
    return ""

  depth = 0
  in_string = False
  escape_next = False
  string_quote = ""
  for idx in range(start_index, len(text)):
    ch = text[idx]
    if in_string:
      if escape_next:
        escape_next = False
      elif ch == "\\":
        escape_next = True
      elif ch == string_quote:
        in_string = False
      continue

    if ch == '"' or ch == "'":
      in_string = True
      string_quote = ch
      continue

    if ch == opener:
      depth += 1
    elif ch == closer:
      depth -= 1
      if depth == 0:
        return text[start_index : idx + 1]

  return ""


def _parse_cisco_certificate_rows_from_sequence(rows) -> list:
  parsed_rows = []
  for row in rows or []:
    certificate = ""
    common_name = ""
    usage = ""
    cert_type = ""
    expiration_date = ""

    if isinstance(row, dict):
      certificate = _html_to_text(str(row.get("certificate") or row.get("certificateName") or row.get("certName") or ""))
      common_name = _html_to_text(str(row.get("commonName") or row.get("common_name") or row.get("cn") or ""))
      usage = _html_to_text(str(row.get("usage") or row.get("certificateUsage") or ""))
      cert_type = _html_to_text(str(row.get("type") or row.get("certificateType") or row.get("certType") or ""))
      expiration_date = _html_to_text(
        str(
          row.get("expirationDate")
          or row.get("expiration")
          or row.get("expires")
          or row.get("validTo")
          or ""
        )
      )

      if not expiration_date:
        dict_values = [_html_to_text(str(v)) for v in row.values()]
        for value in dict_values:
          if re.match(r"^\d{1,2}/\d{1,2}/\d{2,4}$", value):
            expiration_date = value
            break
      if not certificate and not common_name:
        dict_values = [_html_to_text(str(v)) for v in row.values()]
        if len(dict_values) >= 4:
          certificate = dict_values[0]
          common_name = dict_values[1]
          usage = dict_values[2]
          cert_type = dict_values[3]

    elif isinstance(row, (list, tuple)):
      cleaned = [_html_to_text(str(cell)) for cell in row]
      expiration_idx = -1
      for idx, value in enumerate(cleaned):
        if re.match(r"^\d{1,2}/\d{1,2}/\d{2,4}$", value):
          expiration_idx = idx
          break
      if expiration_idx < 0:
        continue
      certificate = cleaned[0] if len(cleaned) > 0 else ""
      common_name = cleaned[1] if len(cleaned) > 1 else ""
      usage = cleaned[2] if len(cleaned) > 2 else ""
      cert_type = cleaned[3] if len(cleaned) > 3 else ""
      expiration_date = cleaned[expiration_idx]
    else:
      continue

    if not expiration_date or not re.match(r"^\d{1,2}/\d{1,2}/\d{2,4}$", expiration_date):
      continue
    if not certificate and not common_name:
      continue

    parsed_rows.append(
      {
        "certificate": certificate,
        "common_name": common_name,
        "usage": usage,
        "type": cert_type,
        "expiration_date": expiration_date,
      }
    )

  return parsed_rows


def _parse_cisco_certificate_json_payload(source_text: str) -> list:
  text = (source_text or "").strip()
  if not text:
    return []

  def _rows_from_obj(obj) -> list:
    if isinstance(obj, list):
      return _parse_cisco_certificate_rows_from_sequence(obj)
    if isinstance(obj, dict):
      for key in ("aaData", "data", "rows", "result", "results"):
        value = obj.get(key)
        if isinstance(value, list):
          parsed = _parse_cisco_certificate_rows_from_sequence(value)
          if parsed:
            return parsed
    return []

  for candidate in [text, unescape(text)]:
    try:
      obj = json.loads(candidate)
      parsed = _rows_from_obj(obj)
      if parsed:
        return parsed
    except Exception:
      pass

  for pattern in [r"(?:aaData|data|rows)\s*[:=]\s*\[", r"(?:aaData|data|rows)\s*[:=]\s*\{"]:
    for match in re.finditer(pattern, text, flags=re.IGNORECASE):
      payload_start = match.end() - 1
      opener = text[payload_start]
      closer = "]" if opener == "[" else "}"
      snippet = _extract_balanced_segment(text, payload_start, opener, closer)
      if not snippet:
        continue
      try:
        obj = json.loads(snippet)
      except Exception:
        continue
      parsed = _rows_from_obj(obj)
      if parsed:
        return parsed

  return []


def _parse_cisco_certificate_table(html_text: str) -> list:
  source = html_text or ""
  if not source:
    return []

  json_rows = _parse_cisco_certificate_json_payload(source)
  if json_rows:
    return json_rows

  rows = []
  for candidate_source in [source, unescape(source)]:
    tr_matches = re.findall(r"<tr[^>]*>(.*?)</tr>", candidate_source, flags=re.IGNORECASE | re.DOTALL)
    for tr_html in tr_matches:
      td_cells = re.findall(r"<td[^>]*>(.*?)</td>", tr_html, flags=re.IGNORECASE | re.DOTALL)
      if len(td_cells) < 5:
        continue

      cleaned = [_html_to_text(cell) for cell in td_cells]

      expiration_idx = -1
      for idx, value in enumerate(cleaned):
        if re.match(r"^\d{1,2}/\d{1,2}/\d{2,4}$", value):
          expiration_idx = idx
          break
      if expiration_idx < 0:
        continue

      certificate = cleaned[0] if len(cleaned) > 0 else ""
      common_name = cleaned[1] if len(cleaned) > 1 else ""
      usage = cleaned[2] if len(cleaned) > 2 else ""
      cert_type = cleaned[3] if len(cleaned) > 3 else ""
      expiration_date = cleaned[expiration_idx]

      if not certificate and not common_name:
        continue

      rows.append(
        {
          "certificate": certificate,
          "common_name": common_name,
          "usage": usage,
          "type": cert_type,
          "expiration_date": expiration_date,
        }
      )

    if rows:
      return rows

  if rows:
    return rows

  return []


def _fetch_platform_certificate_rows(hostname: str, username: str, password: str, timeout_seconds: int = 3) -> tuple[list, str]:
  host = (hostname or "").strip()
  user = (username or "").strip()
  pwd = (password or "").strip()
  if not host:
    return [], "Missing hostname"
  if not user or not pwd:
    return [], "Missing platform credentials"

  base_url = f"https://{host}"
  paths = [
    "/cmplatform/certificateFindList.do?sortColumn=expiration&sortAscend=true",
    "/cmplatform/certificateFindList.do",
    "/cmplatform/certificateList.do",
    "/platform/certificateFindList.do?sortColumn=expiration&sortAscend=true",
    "/platform/certificateFindList.do",
    "/platform/certificateList.do",
    "/cupplatform/certificateFindList.do?sortColumn=expiration&sortAscend=true",
    "/cupplatform/certificateFindList.do",
    "/cupplatform/certificateList.do",
    "/cuplatform/certificateFindList.do?sortColumn=expiration&sortAscend=true",
    "/cuplatform/certificateFindList.do",
    "/cuplatform/certificateList.do",
  ]

  session_obj = requests.Session()
  session_obj.verify = False
  session_obj.trust_env = False
  session_obj.headers.update({"User-Agent": "Mozilla/5.0"})

  def _parse_from_html_or_frames(html_text: str, preferred_auth: tuple | None = None):
    parsed = _parse_cisco_certificate_table(html_text or "")
    if parsed:
      return parsed

    frame_sources = re.findall(r"<(?:frame|iframe)[^>]+src=[\"']([^\"']+)[\"']", html_text or "", flags=re.IGNORECASE)
    for src in frame_sources:
      src_text = (src or "").strip()
      if not src_text or src_text.lower().startswith("javascript:"):
        continue
      frame_url = urljoin(f"{base_url}/", src_text)
      try:
        frame_resp = session_obj.get(
          frame_url,
          auth=preferred_auth,
          timeout=timeout_seconds,
          allow_redirects=True,
        )
        parsed_frame = _parse_cisco_certificate_table(frame_resp.text or "")
        if parsed_frame:
          return parsed_frame
      except Exception:
        continue

    return []

  errors = []
  for path in paths:
    target_url = f"{base_url}{path}"
    try:
      resp = session_obj.get(
        target_url,
        auth=HTTPBasicAuth(user, pwd),
        timeout=timeout_seconds,
        allow_redirects=True,
      )
      parsed = _parse_from_html_or_frames(resp.text or "", preferred_auth=HTTPBasicAuth(user, pwd))
      if parsed:
        return parsed, "OK"

      html_text = (resp.text or "")
      login_endpoints = [
        "/j_security_check",
        "/platform/j_security_check",
        "/cmplatform/j_security_check",
        "/cupplatform/j_security_check",
        "/cuplatform/j_security_check",
        "/cuadmin/j_security_check",
        "/cupadmin/j_security_check",
      ]
      login_payloads = [
        {"j_username": user, "j_password": pwd},
        {"username": user, "password": pwd},
      ]

      # Only attempt form-login retries when the response shape indicates auth flow.
      # Skipping retries on 404 pages keeps deep inventory from hitting gateway timeout.
      response_code = int(resp.status_code or 0)
      response_url = (resp.url or "").lower()
      should_attempt_login = (
        response_code in {200, 401, 403}
        and (
          "j_security_check" in html_text
          or "j_username" in html_text
          or "login" in response_url
        )
      )

      if should_attempt_login:
        for login_path in login_endpoints:
          login_url = f"{base_url}{login_path}"
          for payload in login_payloads:
            try:
              session_obj.post(
                login_url,
                data=payload,
                timeout=timeout_seconds,
                allow_redirects=True,
              )
            except Exception:
              continue

            try:
              resp2 = session_obj.get(target_url, timeout=timeout_seconds, allow_redirects=True)
              parsed2 = _parse_from_html_or_frames(resp2.text or "")
              if parsed2:
                return parsed2, "OK"
            except Exception:
              continue

      errors.append(f"{path}: HTTP {resp.status_code}, final_url={resp.url}")
    except Exception as exc:
      errors.append(f"{path}: {type(exc).__name__}: {exc}")

  return [], " ; ".join(errors) if errors else "Certificate table not found"


def _summarize_platform_inventory_status(fetch_status: str) -> str:
  status_text = str(fetch_status or "").strip()
  lowered = status_text.lower()
  if not status_text:
    return "platform inventory unavailable"
  if "missing platform credentials" in lowered:
    return "missing platform credentials"
  if "missing hostname" in lowered:
    return "missing hostname"
  if "401" in lowered or "403" in lowered:
    return "platform authentication failed"
  if "404" in lowered:
    return "platform certificate page not available"
  if "timeout" in lowered:
    return "platform inventory request timed out"
  if "name or service not known" in lowered or "nodename nor servname" in lowered or "failed to resolve" in lowered:
    return "platform hostname resolution failed"
  if "connection" in lowered or "ssl" in lowered:
    return "platform connection failed"
  if "certificate table not found" in lowered:
    return "platform certificate table not found"
  return "platform inventory unavailable"


def _collect_lab_tls_quick_expiry(target_hostnames: list[str] | None = None) -> list:
  rows = []
  target_hosts = {
    str(item or "").strip().lower()
    for item in (target_hostnames or [])
    if str(item or "").strip()
  }

  for target in LAB_CERT_MANAGER_TARGETS:
    host = str(target.get("hostname", "") or "").strip().lower()
    if host not in LAB_CERT_MANAGER_ALLOWED_HOSTS:
      continue
    if target_hosts and host not in target_hosts:
      continue

    ip = str(target.get("ip", "") or "").strip()
    probe_result = None
    for port in CERT_MANAGER_PROBE_PORTS:
      candidate = _probe_tls_certificate(host, ip, int(port), timeout_seconds=6)
      if candidate.get("reachable"):
        probe_result = candidate
        break
      if probe_result is None:
        probe_result = candidate

    probe_result = probe_result or {}
    days_remaining = probe_result.get("days_remaining")
    status_text = str(probe_result.get("status", "") or "").strip() or "Unknown"
    expiration_text = str(probe_result.get("valid_until", "") or "").strip()
    expiration_short = ""
    if expiration_text:
      expiration_short = expiration_text[:10]
    common_name = str(probe_result.get("common_name", "") or "").strip()

    rows.append(
      {
        "system": str(target.get("system", "") or "").strip(),
        "role": str(target.get("role", "") or "").strip(),
        "hostname": host,
        "certificate": common_name,
        "common_name": common_name,
        "expiration_date_short": expiration_short,
        "expiration_date": expiration_text,
        "days_remaining": days_remaining,
        "status": status_text,
      }
    )

  rows.sort(
    key=lambda row: (
      float("inf") if row.get("days_remaining") is None else int(row.get("days_remaining")),
      str(row.get("hostname", "")),
    )
  )
  return rows


def _probe_tls_certificate(hostname: str, ip_address: str, port: int, timeout_seconds: int = 6) -> dict:
  host = (hostname or "").strip()
  ip = (ip_address or "").strip()
  result = {
    "probe_host": host,
    "probe_ip": ip,
    "probe_port": int(port),
    "reachable": False,
    "valid_until": "",
    "days_remaining": None,
    "issuer": "",
    "subject": "",
    "common_name": "",
    "usage": "Identity",
    "certificate_type": "Unknown",
    "subject_alt_names": [],
    "serial_number": "",
    "sha256_fingerprint": "",
    "status": "Probe failed",
  }

  try:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, int(port)), timeout=float(timeout_seconds)) as sock:
      with context.wrap_socket(sock, server_hostname=host) as tls_sock:
        der_cert = tls_sock.getpeercert(binary_form=True)
        cert = tls_sock.getpeercert() or {}

    if (not cert) and der_cert:
      tmp_path = ""
      try:
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as tmp:
          tmp.write(pem_cert)
          tmp_path = tmp.name
        cert = ssl._ssl._test_decode_cert(tmp_path) or {}
      except Exception:
        cert = cert or {}
      finally:
        if tmp_path:
          try:
            os.unlink(tmp_path)
          except Exception:
            pass

    if not cert:
      result["status"] = "No certificate returned"
      return result

    fingerprint = ""
    if der_cert:
      fingerprint = hashlib.sha256(der_cert).hexdigest().upper()

    not_after_raw = (cert.get("notAfter", "") or "").strip()
    not_after = _parse_certificate_not_after(not_after_raw)
    days_remaining = None
    if not_after:
      delta = not_after - datetime.datetime.now(datetime.timezone.utc)
      days_remaining = int(delta.total_seconds() // 86400)

    common_name = ""
    for part in cert.get("subject", []) or []:
      for key, value in part:
        if key == "commonName":
          common_name = value
          break
      if common_name:
        break

    sans = []
    for san_type, san_value in cert.get("subjectAltName", []) or []:
      if san_type and san_value:
        sans.append(f"{san_type}:{san_value}")

    usage = "Identity"
    ext_usage_values = [str(x or "").strip() for x in (cert.get("extendedKeyUsage", []) or []) if str(x or "").strip()]
    if ext_usage_values and all("TLS Web Server Authentication" not in item for item in ext_usage_values):
      usage = "Trust"

    signature_alg = str(cert.get("signatureAlgorithm", "") or "").upper()
    certificate_type = "Unknown"
    if "RSA" in signature_alg:
      certificate_type = "RSA"
    elif "EC" in signature_alg or "ECDSA" in signature_alg:
      certificate_type = "EC"

    result.update(
      {
        "reachable": True,
        "valid_until": not_after.isoformat() if not_after else not_after_raw,
        "days_remaining": days_remaining,
        "issuer": _extract_cert_name(cert.get("issuer", [])),
        "subject": _extract_cert_name(cert.get("subject", [])),
        "common_name": common_name,
        "usage": usage,
        "certificate_type": certificate_type,
        "subject_alt_names": sans,
        "serial_number": str(cert.get("serialNumber", "") or "").strip(),
        "sha256_fingerprint": fingerprint,
        "status": "OK" if days_remaining is None or days_remaining >= 0 else "Expired",
      }
    )
    return result
  except Exception as exc:
    result["status"] = f"{type(exc).__name__}: {exc}"
    return result


def _collect_lab_certificate_inventory(cucm_user: str, cucm_pass: str, target_hostnames: list[str] | None = None) -> list:
  rows = []
  target_hosts = {
    str(item or "").strip().lower()
    for item in (target_hostnames or [])
    if str(item or "").strip()
  }
  for target in LAB_CERT_MANAGER_TARGETS:
    host = str(target.get("hostname", "") or "").strip().lower()
    if host not in LAB_CERT_MANAGER_ALLOWED_HOSTS:
      continue
    if target_hosts and host not in target_hosts:
      continue

    parsed_rows, fetch_status = _fetch_platform_certificate_rows(host, cucm_user, cucm_pass)
    fetch_summary = _summarize_platform_inventory_status(fetch_status)
    if not parsed_rows:
      probe_result = None
      for port in CERT_MANAGER_PROBE_PORTS:
        candidate = _probe_tls_certificate(host, str(target.get("ip", "") or "").strip(), int(port), timeout_seconds=6)
        if candidate.get("reachable"):
          probe_result = candidate
          break
        if probe_result is None:
          probe_result = candidate

      probe_result = probe_result or {}
      fallback_days = probe_result.get("days_remaining")
      fallback_status = str(probe_result.get("status", "") or "").strip()
      fallback_expiration = str(probe_result.get("valid_until", "") or "").strip()
      fallback_common_name = str(probe_result.get("common_name", "") or "").strip()
      if probe_result.get("reachable") and fallback_expiration:
        rows.append(
          {
            "system": str(target.get("system", "") or "").strip(),
            "role": str(target.get("role", "") or "").strip(),
            "hostname": host,
            "ip": str(target.get("ip", "") or "").strip(),
            "certificate": fallback_common_name,
            "usage": "TLS probe fallback",
            "type": "Leaf",
            "expiration_date": fallback_expiration,
            "days_remaining": fallback_days,
            "common_name": fallback_common_name,
            "issuer": str(probe_result.get("issuer", "") or "").strip(),
            "status": f"TLS fallback used: {fetch_summary}",
          }
        )
        continue

      rows.append(
        {
          "system": str(target.get("system", "") or "").strip(),
          "role": str(target.get("role", "") or "").strip(),
          "hostname": host,
          "ip": str(target.get("ip", "") or "").strip(),
          "certificate": "",
          "usage": "",
          "type": "",
          "expiration_date": "",
          "days_remaining": None,
          "common_name": "",
          "issuer": "",
          "status": f"Fetch failed: {fetch_summary or fallback_status or 'platform inventory unavailable'}",
        }
      )
      continue

    for cert_row in parsed_rows:
      expiration_date = str(cert_row.get("expiration_date", "") or "").strip()
      expiration_obj = _parse_platform_expiration_date(expiration_date)
      days_remaining = None
      if expiration_obj:
        days_remaining = (expiration_obj - datetime.datetime.now(datetime.timezone.utc).date()).days

      rows.append(
        {
          "system": str(target.get("system", "") or "").strip(),
          "role": str(target.get("role", "") or "").strip(),
          "hostname": host,
          "ip": str(target.get("ip", "") or "").strip(),
          "certificate": str(cert_row.get("certificate", "") or "").strip(),
          "usage": str(cert_row.get("usage", "") or "").strip(),
          "type": str(cert_row.get("type", "") or "").strip(),
          "expiration_date": expiration_date,
          "days_remaining": days_remaining,
          "common_name": str(cert_row.get("common_name", "") or "").strip(),
          "issuer": "",
          "status": "Expired" if (days_remaining is not None and days_remaining < 0) else "OK",
        }
      )
  return rows


def _prune_cert_renewal_runs_locked(max_runs: int = CERT_RENEWAL_MAX_RUNS):
  if len(CERT_RENEWAL_RUNS) <= max_runs:
    return
  sorted_runs = sorted(
    CERT_RENEWAL_RUNS.items(),
    key=lambda kv: float(kv[1].get("created_epoch", 0) or 0),
  )
  for run_id, _ in sorted_runs[:-max_runs]:
    CERT_RENEWAL_RUNS.pop(run_id, None)


def _build_renewal_step_template() -> dict:
  return {
    "precheck": {"status": "pending", "detail": "Not started", "updated_at": ""},
    "generate_csr": {"status": "pending", "detail": "Not started", "updated_at": ""},
    "upload_signed_cert": {"status": "pending", "detail": "Not started", "updated_at": ""},
    "restart_services": {"status": "pending", "detail": "Not started", "updated_at": ""},
    "final_validate": {"status": "pending", "detail": "Not started", "updated_at": ""},
  }


def _create_cert_renewal_run(operator: str, target_hosts: list[str]) -> dict:
  now_utc = datetime.datetime.now(datetime.timezone.utc)
  run_id = str(uuid4())
  host_states = {}
  for host in target_hosts:
    host_states[host] = {
      "hostname": host,
      "steps": _build_renewal_step_template(),
    }

  run = {
    "run_id": run_id,
    "operator": operator,
    "target_hosts": list(target_hosts),
    "created_at": now_utc.isoformat(),
    "created_epoch": time.time(),
    "updated_at": now_utc.isoformat(),
    "status": "active",
    "hosts": host_states,
    "history": [
      {
        "at": now_utc.isoformat(),
        "event": "run_created",
        "detail": f"Renewal run created for {', '.join(target_hosts)}",
      }
    ],
  }
  return run


def _snapshot_cert_renewal_run(run: dict) -> dict:
  return json.loads(json.dumps(run))


def _set_cert_run_step_status(run: dict, host: str, step: str, status: str, detail: str):
  now_text = datetime.datetime.now(datetime.timezone.utc).isoformat()
  host_state = ((run or {}).get("hosts", {}) or {}).get(host, {})
  steps = host_state.get("steps", {}) if isinstance(host_state, dict) else {}
  step_state = steps.get(step, {}) if isinstance(steps, dict) else {}
  if not isinstance(step_state, dict):
    step_state = {}
    steps[step] = step_state

  step_state["status"] = status
  step_state["detail"] = detail
  step_state["updated_at"] = now_text
  run["updated_at"] = now_text
  run.setdefault("history", []).append(
    {
      "at": now_text,
      "event": f"{step}:{status}",
      "detail": f"{host}: {detail}",
    }
  )


def _split_pem_certificates(chain_text: str) -> list[str]:
  source = chain_text or ""
  matches = re.findall(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    source,
    flags=re.DOTALL,
  )
  normalized = []
  for cert in matches:
    clean = (cert or "").strip()
    if not clean:
      continue
    if not clean.endswith("\n"):
      clean += "\n"
    normalized.append(clean)
  return normalized


def _vos_api_request(host: str, user: str, pwd: str, method: str, path: str, payload: dict | None = None, timeout_seconds: int = 30):
  url = f"https://{host}{path}"
  headers = {"Accept": "application/json"}
  if payload is not None:
    headers["Content-Type"] = "application/json"

  response = requests.request(
    method=method.upper(),
    url=url,
    auth=HTTPBasicAuth(user, pwd),
    json=payload,
    headers=headers,
    verify=False,
    timeout=timeout_seconds,
    allow_redirects=True,
  )
  parsed = None
  try:
    parsed = response.json()
  except Exception:
    parsed = None

  return response.status_code, parsed, (response.text or ""), (response.url or url)


def _extract_csr_from_payload(data, fallback_text: str = "") -> str:
  def _walk(node):
    if isinstance(node, dict):
      for key in ["csr", "csrPem", "pkcs10", "certificateSigningRequest", "request"]:
        value = node.get(key)
        if isinstance(value, str) and "BEGIN CERTIFICATE REQUEST" in value:
          return value
      for value in node.values():
        found = _walk(value)
        if found:
          return found
    elif isinstance(node, list):
      for item in node:
        found = _walk(item)
        if found:
          return found
    return ""

  found = _walk(data)
  if found:
    return found.strip()

  match = re.search(
    r"-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----",
    fallback_text or "",
    flags=re.DOTALL,
  )
  if match:
    return match.group(0).strip()
  return ""


def _renewal_precheck_host(host: str, user: str, pwd: str) -> tuple[bool, str]:
  checks = [
    "/platformcom/api/v1/certmgr/config/trust/certificate?service=tomcat",
    "/platformcom/api/v1/certmgr/config/identity/certificates?service=tomcat",
    "/platformcom/api/v1/certmgr/config/identity/certificate?service=tomcat",
  ]
  errors = []
  for path in checks:
    try:
      status_code, _, _, final_url = _vos_api_request(host, user, pwd, "GET", path, payload=None)
      if 200 <= int(status_code) < 300:
        return True, f"Precheck OK via {path}"
      errors.append(f"{path}: HTTP {status_code}, final_url={final_url}")
    except Exception as exc:
      errors.append(f"{path}: {type(exc).__name__}: {exc}")
  return False, " ; ".join(errors)


def _renewal_generate_csr_host(host: str, user: str, pwd: str, cert_alias: str) -> tuple[bool, str, str]:
  alias = (cert_alias or "tomcat").strip() or "tomcat"
  endpoint = "/platformcom/api/v1/certmgr/config/csr"
  payloads = [
    {"service": "tomcat", "certificate": alias},
    {"service": "tomcat", "certName": alias},
    {"service": "tomcat", "name": alias},
  ]

  attempts = []
  for payload in payloads:
    try:
      status_code, parsed, body_text, final_url = _vos_api_request(host, user, pwd, "POST", endpoint, payload=payload)
      csr_text = _extract_csr_from_payload(parsed, body_text)
      if 200 <= int(status_code) < 300 and csr_text:
        return True, f"CSR generated via payload keys {', '.join(payload.keys())}", csr_text
      attempts.append(f"HTTP {status_code} final_url={final_url} payload={payload}")
    except Exception as exc:
      attempts.append(f"{payload}: {type(exc).__name__}: {exc}")

  return False, "CSR generation failed: " + " ; ".join(attempts), ""


def _renewal_upload_signed_chain_host(host: str, user: str, pwd: str, signed_chain_pem: str) -> tuple[bool, str]:
  certificates = _split_pem_certificates(signed_chain_pem)
  if not certificates:
    return False, "No PEM certificates found in signed chain input"

  trust_endpoint = "/platformcom/api/v1/certmgr/config/trust/certificates"
  identity_endpoint = "/platformcom/api/v1/certmgr/config/identity/certificates"

  trust_certs = certificates[1:] if len(certificates) > 1 else []
  if trust_certs:
    trust_payloads = [
      {"service": ["tomcat"], "certificates": trust_certs, "description": "Trust Certificate"},
      {"service": "tomcat", "certificates": trust_certs, "description": "Trust Certificate"},
    ]
    trust_ok = False
    trust_errors = []
    for payload in trust_payloads:
      try:
        status_code, _, _, final_url = _vos_api_request(host, user, pwd, "POST", trust_endpoint, payload=payload)
        if 200 <= int(status_code) < 300:
          trust_ok = True
          break
        trust_errors.append(f"HTTP {status_code}, final_url={final_url}")
      except Exception as exc:
        trust_errors.append(f"{type(exc).__name__}: {exc}")
    if not trust_ok and trust_errors:
      return False, "Trust certificate upload failed: " + " ; ".join(trust_errors)

  identity_payloads = [
    {"service": "tomcat", "certificates": certificates},
    {"service": ["tomcat"], "certificates": certificates},
  ]
  identity_errors = []
  for payload in identity_payloads:
    try:
      status_code, _, _, final_url = _vos_api_request(host, user, pwd, "POST", identity_endpoint, payload=payload)
      if 200 <= int(status_code) < 300:
        return True, "Identity certificate chain uploaded"
      identity_errors.append(f"HTTP {status_code}, final_url={final_url}")
    except Exception as exc:
      identity_errors.append(f"{type(exc).__name__}: {exc}")

  return False, "Identity upload failed: " + " ; ".join(identity_errors)


def _renewal_restart_services_host(host: str, user: str, pwd: str) -> tuple[bool, str]:
  attempts = [
    ("/platformcom/api/v1/service/restart", {"services": ["Cisco Tomcat"]}),
    ("/platformcom/api/v1/services/restart", {"service": "Cisco Tomcat"}),
    ("/platformcom/api/v1/utils/service/restart", {"service": "Cisco Tomcat"}),
  ]
  errors = []
  for path, payload in attempts:
    try:
      status_code, _, _, final_url = _vos_api_request(host, user, pwd, "POST", path, payload=payload)
      if 200 <= int(status_code) < 300:
        return True, f"Tomcat restart initiated via {path}"
      errors.append(f"{path}: HTTP {status_code}, final_url={final_url}")
    except Exception as exc:
      errors.append(f"{path}: {type(exc).__name__}: {exc}")

  manual = f"API restart not confirmed. Run manually on {host}: utils service restart Cisco Tomcat"
  return False, manual + (" ; attempts: " + " ; ".join(errors) if errors else "")


def _renewal_final_validate_host(host: str, user: str, pwd: str, cert_alias: str) -> tuple[bool, str]:
  alias = (cert_alias or "tomcat").strip().lower()
  rows, status = _fetch_platform_certificate_rows(host, user, pwd)
  if rows:
    matching = [
      row for row in rows
      if alias in str(row.get("certificate", "") or "").strip().lower()
    ]
    candidate_rows = matching if matching else rows
    candidate_rows.sort(key=lambda row: str(row.get("expiration_date", "") or ""))
    best = candidate_rows[0] if candidate_rows else {}
    exp = str(best.get("expiration_date", "") or "").strip()
    cert_name = str(best.get("certificate", "") or "").strip()
    return True, f"Inventory validate OK: {cert_name or '(unknown cert)'} expires {exp or '(unknown)'}"

  tls = _probe_tls_certificate(host, "", 8443)
  if tls.get("reachable"):
    return True, f"TLS probe reachable; cert validation fallback used ({tls.get('status', 'OK')})"
  return False, f"Final validation failed: {status}"


def _check_aerialink_feasibility(force_refresh: bool = False) -> dict:
  now_epoch = time.time()
  cache_key = "aerialink"

  with INTEGRATION_FEASIBILITY_LOCK:
    cached = INTEGRATION_FEASIBILITY_CACHE.get(cache_key)
    if cached and not force_refresh and (now_epoch - float(cached.get("checked_at", 0) or 0)) < INTEGRATION_FEASIBILITY_TTL_SECONDS:
      return dict(cached)

  result = {
    "integration": "aerialink",
    "ok": False,
    "status": "Unknown",
    "hint": "",
    "checked_at": now_epoch,
  }

  if not AERIALINK_V5_BASE_URL:
    result["status"] = "Aerialink base URL not configured"
    result["hint"] = "Set AERIALINK_V5_BASE_URL in environment settings."
  elif not AERIALINK_USERNAME or not AERIALINK_PASSWORD:
    result["status"] = "Aerialink credentials not configured"
    result["hint"] = "Set AERIALINK_USERNAME and AERIALINK_PASSWORD in environment settings."
  else:
    try:
      endpoint_path = AERIALINK_ACCOUNT_CODE_LOOKUP_PATH or "/codes"
      endpoint_path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
      probe_url = f"{AERIALINK_V5_BASE_URL}{endpoint_path}"
      resp = requests.get(
        probe_url,
        params={"codes": "10000000000"},
        headers={"Accept": "application/json"},
        auth=HTTPBasicAuth(AERIALINK_USERNAME, AERIALINK_PASSWORD),
        verify=False,
        timeout=20,
      )

      if resp.status_code == 200:
        result["ok"] = True
        result["status"] = "Aerialink API reachable"
      elif resp.status_code in {401, 403}:
        result["status"] = f"Aerialink authentication failed (HTTP {resp.status_code})"
        result["hint"] = "Verify AERIALINK_USERNAME/AERIALINK_PASSWORD and account permissions."
      elif resp.status_code == 404:
        result["status"] = "Aerialink lookup endpoint not found (HTTP 404)"
        result["hint"] = "Verify AERIALINK_ACCOUNT_CODE_LOOKUP_PATH against your account API documentation."
      else:
        result["status"] = f"Aerialink API probe failed (HTTP {resp.status_code})"
        result["hint"] = "Confirm endpoint path, credentials, and network egress from this host."
    except Exception as exc:
      result["status"] = f"Aerialink API probe error: {exc}"
      result["hint"] = "Confirm DNS/network reachability and TLS policy from this host."

  with INTEGRATION_FEASIBILITY_LOCK:
    INTEGRATION_FEASIBILITY_CACHE[cache_key] = dict(result)

  return result


def _is_public_path(path: str):
  return path in {"/", "/login", "/genesys-admin", "/genesys/users/extract", "/healthz"}


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
    "/translation-pattern/twilio-inbound-verification",
    "/bulk/lookup/person",
    "/bulk/lookup/extension",
    "/verasmart/lab/queue/upload",
    "/verasmart/lab/queue/status",
    "/check/user-devices",
    "/strike-mask/apply",
    "/strike-mask/reverse",
    "/strike-mask/options",
    "/strike-mask/in-use",
    "/lookup/sms-number-look",
    "/twilio/amieweb/sms-host",
    "/cert-manager/lab/inventory",
    "/ops/integrations/feasibility",
    "/ops/parity-report",
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
  message_lower = message.lower()
  status_code = 401 if (
    "authentication required" in message_lower
    or "log in again" in message_lower
    or "credentials expired" in message_lower
  ) else 400

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
  logger.exception("Unhandled exception on %s", request.url.path, exc_info=exc)
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


# ---------------------------------------------------------------------------
# Separation SMS Report — scheduled email for offboarded employees
# ---------------------------------------------------------------------------

def _separation_report_read_offboard_rows(start_dt: datetime.datetime, end_dt: datetime.datetime) -> list[dict]:
  """Return audit rows for offboard_user_option_10 whose timestamp falls in [start_dt, end_dt)."""
  if not os.path.exists(AUDIT_LOG_PATH):
    return []
  try:
    with AUDIT_LOG_LOCK:
      with open(AUDIT_LOG_PATH, "r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
  except Exception:
    return []

  matched = []
  for row in rows:
    if (row.get("action") or "").strip() != "offboard_user_option_10":
      continue
    ts_text = (row.get("timestamp") or "").strip()
    if not ts_text:
      continue
    try:
      ts = datetime.datetime.strptime(ts_text, AUDIT_TIMESTAMP_FORMAT)
    except ValueError:
      continue
    if start_dt <= ts < end_dt:
      matched.append(row)
  return matched


def _separation_report_build_sms_rows(offboard_rows: list[dict]) -> list[dict]:
  """For each offboard row, look up every deleted extension in SMS platforms."""
  results = []
  for row in offboard_rows:
    account = (row.get("account") or "").strip()
    ext_deleted_raw = (row.get("extension_deleted") or "").strip()
    if not ext_deleted_raw or ext_deleted_raw.lower() == "none":
      continue
    extensions = [e.strip() for e in ext_deleted_raw.split("|") if e.strip()]
    for ext in extensions:
      telephone = ext

      twilio_default = _lookup_twilio_number_by_phone(telephone, account="default")
      twilio_sfdc = _lookup_twilio_number_by_phone(telephone, account="salesforce")
      aerialink = _lookup_aerialink_account_code_by_phone(telephone)

      found_in_parts = []
      if twilio_default.get("found"):
        found_in_parts.append("Twilio - AMIEWeb")
      if twilio_sfdc.get("found"):
        found_in_parts.append("Twilio - Salesforce")
      if aerialink.get("provisioned"):
        found_in_parts.append("Aerialink Classic")

      sms_number = (
        (twilio_default.get("phone_number") or "").strip()
        or (twilio_sfdc.get("phone_number") or "").strip()
        or (aerialink.get("matched_number") or "").strip()
        or _normalize_phone_to_e164(telephone)
        or telephone
      )

      configured_in = ", ".join(found_in_parts) if found_in_parts else "Not Found"

      results.append({
        "account": account,
        "extension": ext,
        "sms_number": sms_number or "-",
        "configured_in": configured_in,
        "timestamp": (row.get("timestamp") or "").strip(),
        "operator": (row.get("operator") or "").strip(),
        "cucm_host": (row.get("cucm_host") or "").strip(),
      })

  # Sort by configured_in (Not Found last), then by account name
  def _sort_key(r: dict):
    ci = r.get("configured_in", "")
    return (0 if ci and ci != "Not Found" else 1, ci, r.get("account", ""))

  results.sort(key=_sort_key)
  return results


def _separation_report_build_html(sms_rows: list[dict], date_range_label: str) -> str:
  """Build the HTML email body for the separation SMS report."""
  row_html_parts = []
  for r in sms_rows:
    bg = "#fff8e1" if r["configured_in"] == "Not Found" else "#ffffff"
    badge_color = "#e53935" if r["configured_in"] == "Not Found" else "#1565c0"
    row_html_parts.append(
      f'<tr style="background:{bg}">'
      f'<td style="padding:8px 12px;border-bottom:1px solid #eee">{escape(r["account"])}</td>'
      f'<td style="padding:8px 12px;border-bottom:1px solid #eee;font-family:monospace">{escape(r["extension"])}</td>'
      f'<td style="padding:8px 12px;border-bottom:1px solid #eee;font-family:monospace">{escape(r["sms_number"])}</td>'
      f'<td style="padding:8px 12px;border-bottom:1px solid #eee">'
      f'<span style="background:{badge_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">'
      f'{escape(r["configured_in"])}</span></td>'
      f'<td style="padding:8px 12px;border-bottom:1px solid #eee;color:#888;font-size:12px">{escape(r["timestamp"])}</td>'
      f'</tr>'
    )
  rows_html = "\n".join(row_html_parts) if row_html_parts else (
    '<tr><td colspan="5" style="padding:16px;text-align:center;color:#888">No offboarded employees with extensions found in this period.</td></tr>'
  )

  found_count = sum(1 for r in sms_rows if r["configured_in"] != "Not Found")
  not_found_count = len(sms_rows) - found_count

  return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;color:#333;margin:0;padding:0">
<div style="max-width:900px;margin:24px auto;background:#fff;border:1px solid #ddd;border-radius:8px;overflow:hidden">
  <div style="background:#1a237e;color:#fff;padding:20px 28px">
    <h2 style="margin:0 0 4px 0">Separation SMS Number Report</h2>
    <p style="margin:0;font-size:14px;opacity:.85">Period: {escape(date_range_label)}</p>
  </div>
  <div style="padding:20px 28px">
    <p style="margin:0 0 16px 0;font-size:14px">
      The following extensions were removed via the <strong>Offboard User (Option 10)</strong> workflow during the report period.
      Numbers found in SMS platforms should be reviewed for removal from Twilio or Aerialink.
    </p>
    <div style="display:flex;gap:16px;margin-bottom:20px">
      <div style="background:#e3f2fd;border-radius:6px;padding:12px 20px;flex:1;text-align:center">
        <div style="font-size:28px;font-weight:bold;color:#1565c0">{found_count}</div>
        <div style="font-size:12px;color:#555">Found in SMS Platform</div>
      </div>
      <div style="background:#fff8e1;border-radius:6px;padding:12px 20px;flex:1;text-align:center">
        <div style="font-size:28px;font-weight:bold;color:#e65100">{not_found_count}</div>
        <div style="font-size:12px;color:#555">Not Found / Already Removed</div>
      </div>
      <div style="background:#f3e5f5;border-radius:6px;padding:12px 20px;flex:1;text-align:center">
        <div style="font-size:28px;font-weight:bold;color:#6a1b9a">{len(sms_rows)}</div>
        <div style="font-size:12px;color:#555">Total Extensions Checked</div>
      </div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <thead>
        <tr style="background:#f5f5f5">
          <th style="padding:10px 12px;text-align:left;border-bottom:2px solid #ddd">Employee (Account)</th>
          <th style="padding:10px 12px;text-align:left;border-bottom:2px solid #ddd">Extension</th>
          <th style="padding:10px 12px;text-align:left;border-bottom:2px solid #ddd">SMS Number</th>
          <th style="padding:10px 12px;text-align:left;border-bottom:2px solid #ddd">Configured In</th>
          <th style="padding:10px 12px;text-align:left;border-bottom:2px solid #ddd">Offboarded At</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
    <p style="margin:20px 0 0 0;font-size:12px;color:#aaa">
      This is an automated report from the CUCM Voice Automation Portal.
      Removal from Twilio/Aerialink is a manual process — this email serves as notification only.
    </p>
  </div>
</div>
</body>
</html>"""


def _run_separation_sms_report(triggered_by: str = "scheduler") -> dict:
  """
  Run the separation SMS report for the configured lookback window.
  Returns a summary dict with keys: success, numbers_found, numbers_emailed, error.
  """
  try:
    cfg = _get_sep_report_settings()
    tz = ZoneInfo("America/Los_Angeles")
    now_pst = datetime.datetime.now(tz=tz).replace(tzinfo=None)

    frequency = cfg["frequency"]

    if frequency == "weekly":
      # Previous Mon 00:00 → previous Sun 23:59:59
      today_weekday = now_pst.weekday()  # 0=Mon
      days_since_monday = today_weekday
      last_monday = (now_pst - datetime.timedelta(days=days_since_monday + 7)).replace(
        hour=0, minute=0, second=0, microsecond=0
      )
      end_dt = last_monday + datetime.timedelta(days=7)  # this Monday 00:00 == prior Sunday end
      start_dt = last_monday
      date_range_label = f"{start_dt.strftime('%Y-%m-%d')} (Mon) through {(end_dt - datetime.timedelta(seconds=1)).strftime('%Y-%m-%d')} (Sun)"
    else:
      # Previous calendar day
      yesterday = now_pst - datetime.timedelta(days=1)
      start_dt = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
      end_dt = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999) + datetime.timedelta(microseconds=1)
      date_range_label = start_dt.strftime("%Y-%m-%d")

    offboard_rows = _separation_report_read_offboard_rows(start_dt, end_dt)
    sms_rows = _separation_report_build_sms_rows(offboard_rows)

    numbers_checked = [r["sms_number"] for r in sms_rows if r["sms_number"] != "-"]
    extensions_checked = [r["extension"] for r in sms_rows]

    subject = f"[CUCM] Separation SMS Number Report — {date_range_label}"
    html_body = _separation_report_build_html(sms_rows, date_range_label)
    plain_body = (
      f"Separation SMS Number Report\nPeriod: {date_range_label}\n\n"
      + "\n".join(
        f"  {r['account']} | ext {r['extension']} | SMS {r['sms_number']} | {r['configured_in']}"
        for r in sms_rows
      )
      + (
        "\n\nNo extensions found." if not sms_rows else ""
      )
      + "\n\nRemoval from Twilio/Aerialink is manual — this email is for notification only."
    )

    recipient = cfg["recipient"]
    recipient_2 = cfg["recipient_2"]
    recipients = [r for r in [recipient, recipient_2] if r]
    sender = cfg["from_address"] or "noreply@amnhealthcare.com"

    _send_smtp_email(
      sender=sender,
      recipients=recipients,
      subject=subject,
      body=plain_body,
      html_body=html_body,
    )

    # Log the send to the audit trail — extension_deleted holds all numbers included
    numbers_pipe = "|".join(extensions_checked) if extensions_checked else "none"
    recipients_logged = "|".join(recipients)
    _append_audit_event(
      action="separation_sms_report_sent",
      cucm_host="",
      operator=triggered_by,
      target=f"period={date_range_label};extensions_checked={len(extensions_checked)}",
      account=recipients_logged,
      extension_added="",
      extension_deleted=numbers_pipe,
      output_filename=f"separation_sms_report_{start_dt.strftime('%Y%m%d')}.html",
      inline_mode=False,
    )

    return {
      "success": True,
      "numbers_checked": len(extensions_checked),
      "numbers_found_in_sms": sum(1 for r in sms_rows if r["configured_in"] != "Not Found"),
      "date_range": date_range_label,
      "recipients": recipients,
      "error": None,
    }
  except Exception as exc:
    logger.error("separation_sms_report failed: %s", exc, exc_info=True)
    return {"success": False, "error": str(exc)}


def _separation_report_scheduler_loop():
  """Daemon thread: fires _run_separation_sms_report at the configured PST time."""
  tz = ZoneInfo("America/Los_Angeles")
  _DAY_ABBR = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

  while True:
    try:
      time.sleep(60)
      cfg = _get_sep_report_settings()
      if not cfg["enabled"]:
        continue

      now = datetime.datetime.now(tz=tz)
      # Only fire at the configured hour:minute window (within the current minute)
      if now.hour != cfg["hour"] or now.minute != cfg["minute"]:
        continue

      frequency = cfg["frequency"]
      if frequency == "weekly":
        target_weekday = _DAY_ABBR.index(cfg["weekly_day"]) if cfg["weekly_day"] in _DAY_ABBR else 0
        if now.weekday() != target_weekday:
          continue

      fire_key = now.strftime("%Y-%m-%d")
      with _SEPARATION_REPORT_SCHEDULER_LOCK:
        last_fired = _SEPARATION_REPORT_SCHEDULER_LAST_FIRED.get("last")
        if last_fired == fire_key:
          continue
        _SEPARATION_REPORT_SCHEDULER_LAST_FIRED["last"] = fire_key

      logger.info("separation_sms_report: firing report for key=%s", fire_key)
      result = _run_separation_sms_report(triggered_by="scheduler")
      logger.info("separation_sms_report: result=%s", result)

    except Exception as exc:
      logger.error("separation_report_scheduler_loop error: %s", exc, exc_info=True)


# Start the separation SMS report scheduler daemon thread at import time.
_sep_report_thread = threading.Thread(target=_separation_report_scheduler_loop, name="sep-sms-report-scheduler", daemon=True)
_sep_report_thread.start()


# ---------------------------------------------------------------------------
# DN Availability Report — scheduled email for number pool monitoring
# ---------------------------------------------------------------------------
_DN_REPORT_ROUTE_PARTITION = "ENT_DEVICE_PT"
_DN_REPORT_SCHEDULER_LAST_FIRED: dict[str, str] = {}
_DN_REPORT_SCHEDULER_LOCK = threading.Lock()


def _axl_list_dns_by_prefix(cucm_host: str, cucm_user: str, cucm_pass: str, prefix: str) -> dict:
  """Return total and unassigned (no device) DN counts for a given prefix in ENT_DEVICE_PT."""
  session = requests.Session()
  session.verify = False
  session.auth = HTTPBasicAuth(cucm_user, cucm_pass)
  soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
  <soapenv:Body>
    <axl:listLine>
      <searchCriteria>
        <pattern>{xml_escape(prefix)}%</pattern>
      </searchCriteria>
      <returnedTags>
        <pattern/>
        <routePartitionName/>
        <deviceName/>
      </returnedTags>
    </axl:listLine>
  </soapenv:Body>
</soapenv:Envelope>"""
  resp = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=soap.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    timeout=60,
    verify=False,
  )
  if resp.status_code != 200:
    raise RuntimeError(f"listLine for prefix {prefix} failed (HTTP {resp.status_code})")

  root = ET.fromstring(resp.text)
  total = 0
  available = 0
  for elem in root.iter():
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    if tag != "line":
      continue
    pattern_val = ""
    partition_val = ""
    device_name = ""
    for child in list(elem):
      ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
      txt = (child.text or "").strip()
      if ctag == "pattern":
        pattern_val = txt
      elif ctag == "routePartitionName":
        partition_val = txt
      elif ctag == "deviceName":
        device_name = txt
    if not pattern_val or partition_val != _DN_REPORT_ROUTE_PARTITION:
      continue
    total += 1
    if not device_name:
      available += 1

  return {"total": total, "available": available, "in_use": total - available}


def _dn_report_build_html(results: list[dict], run_at: str, cucm_host: str, low_threshold: int) -> str:
  """Build the HTML email body for the DN availability report."""
  row_parts = []
  for r in results:
    avail = r["available"]
    total = r["total"]
    in_use = r["in_use"]
    if avail == 0:
      status_label = "CRITICAL — NONE LEFT"
      status_color = "#b71c1c"
      row_bg = "#fff5f5"
      badge_bg = "#b71c1c"
    elif avail < low_threshold:
      status_label = f"LOW — order more soon"
      status_color = "#e65100"
      row_bg = "#fff8e1"
      badge_bg = "#e65100"
    else:
      status_label = "OK"
      status_color = "#1b5e20"
      row_bg = "#ffffff"
      badge_bg = "#2e7d32"

    pct = f"{int(avail / total * 100)}%" if total else "N/A"
    row_parts.append(
      f'<tr style="background:{row_bg}">'
      f'<td style="padding:10px 14px;border-bottom:1px solid #eee;font-weight:600">{escape(r["label"])}</td>'
      f'<td style="padding:10px 14px;border-bottom:1px solid #eee;font-family:monospace">{escape(r["prefix"])}xxx</td>'
      f'<td style="padding:10px 14px;border-bottom:1px solid #eee;font-size:20px;font-weight:700;color:{status_color}">{avail}</td>'
      f'<td style="padding:10px 14px;border-bottom:1px solid #eee">{in_use}</td>'
      f'<td style="padding:10px 14px;border-bottom:1px solid #eee">{total}</td>'
      f'<td style="padding:10px 14px;border-bottom:1px solid #eee">{pct}</td>'
      f'<td style="padding:10px 14px;border-bottom:1px solid #eee">'
      f'<span style="background:{badge_bg};color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600">'
      f'{escape(status_label)}</span></td>'
      f'</tr>'
    )

  rows_html = "\n".join(row_parts) if row_parts else (
    '<tr><td colspan="7" style="padding:16px;text-align:center;color:#888">No DN data returned.</td></tr>'
  )

  critical_count = sum(1 for r in results if r["available"] == 0)
  low_count = sum(1 for r in results if 0 < r["available"] < low_threshold)
  ok_count = sum(1 for r in results if r["available"] >= low_threshold)

  alert_banner = ""
  if critical_count:
    alert_banner = f'<div style="background:#b71c1c;color:#fff;padding:12px 20px;border-radius:6px;margin-bottom:16px;font-weight:600">⚠️ {critical_count} DN type(s) have ZERO available numbers — order immediately!</div>'
  elif low_count:
    alert_banner = f'<div style="background:#e65100;color:#fff;padding:12px 20px;border-radius:6px;margin-bottom:16px;font-weight:600">⚠️ {low_count} DN type(s) are running LOW (below threshold of {low_threshold}) — consider ordering more soon.</div>'

  return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;color:#333;margin:0;padding:0">
<div style="max-width:860px;margin:24px auto;background:#fff;border:1px solid #ddd;border-radius:8px;overflow:hidden">
  <div style="background:#1a237e;color:#fff;padding:20px 28px">
    <h2 style="margin:0 0 4px 0">DN Number Pool Availability Report</h2>
    <p style="margin:0;font-size:14px;opacity:.85">CUCM Host: {escape(cucm_host)} &nbsp;|&nbsp; Run at: {escape(run_at)}</p>
  </div>
  <div style="padding:20px 28px">
    {alert_banner}
    <div style="display:flex;gap:14px;margin-bottom:20px">
      <div style="background:#e8f5e9;border-radius:6px;padding:12px 20px;flex:1;text-align:center">
        <div style="font-size:26px;font-weight:bold;color:#2e7d32">{ok_count}</div>
        <div style="font-size:12px;color:#555">Types OK</div>
      </div>
      <div style="background:#fff8e1;border-radius:6px;padding:12px 20px;flex:1;text-align:center">
        <div style="font-size:26px;font-weight:bold;color:#e65100">{low_count}</div>
        <div style="font-size:12px;color:#555">Types Low</div>
      </div>
      <div style="background:#ffebee;border-radius:6px;padding:12px 20px;flex:1;text-align:center">
        <div style="font-size:26px;font-weight:bold;color:#b71c1c">{critical_count}</div>
        <div style="font-size:12px;color:#555">Types Critical</div>
      </div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <thead>
        <tr style="background:#f5f5f5">
          <th style="padding:9px 14px;text-align:left;border-bottom:2px solid #ddd">DN Type</th>
          <th style="padding:9px 14px;text-align:left;border-bottom:2px solid #ddd">Prefix Range</th>
          <th style="padding:9px 14px;text-align:left;border-bottom:2px solid #ddd">Available</th>
          <th style="padding:9px 14px;text-align:left;border-bottom:2px solid #ddd">In Use</th>
          <th style="padding:9px 14px;text-align:left;border-bottom:2px solid #ddd">Total</th>
          <th style="padding:9px 14px;text-align:left;border-bottom:2px solid #ddd">Avail %</th>
          <th style="padding:9px 14px;text-align:left;border-bottom:2px solid #ddd">Status</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
    <p style="margin:18px 0 0 0;font-size:12px;color:#aaa">
      Low threshold: {low_threshold} numbers. Available = inactive DNs in ENT_DEVICE_PT.
      This is an automated report from the CUCM Voice Automation Portal.
    </p>
  </div>
</div>
</body>
</html>"""


def _run_dn_availability_report(triggered_by: str = "scheduler") -> dict:
  """Run the DN availability report and email results. Returns summary dict."""
  try:
    cfg = _get_dn_report_settings()
    cucm_host = cfg["cucm_host"]
    cucm_user = cfg["cucm_user"]
    cucm_pass = cfg["cucm_pass"]
    if not cucm_host or not cucm_user or not cucm_pass:
      raise RuntimeError("CUCM credentials for DN report not configured. Set them in the DN Availability Report panel on Page 2.")

    dn_map = _get_dn_mapping()
    run_at = _audit_now().strftime(AUDIT_TIMESTAMP_FORMAT)
    low_threshold = cfg["low_threshold"]

    results = []
    errors = []
    for key, (prefix, label) in dn_map.items():
      try:
        counts = _axl_list_dns_by_prefix(cucm_host, cucm_user, cucm_pass, prefix)
        results.append({"key": key, "label": label, "prefix": prefix, **counts})
      except Exception as exc:
        errors.append(f"{label} ({prefix}): {exc}")
        results.append({"key": key, "label": label, "prefix": prefix, "total": 0, "available": 0, "in_use": 0})

    # Sort: General FTE, Recruiter, Strike (by label alphabetically fallback)
    order = {"General FTE": 0, "Recruiter": 1, "Strike": 2}
    results.sort(key=lambda r: order.get(r["label"], 99))

    subject = f"[CUCM] DN Number Pool Report — {run_at[:10]}"
    html_body = _dn_report_build_html(results, run_at, cucm_host, low_threshold)
    plain_lines = [f"DN Number Pool Availability Report — {run_at}", f"CUCM: {cucm_host}", ""]
    for r in results:
      plain_lines.append(f"  {r['label']} ({r['prefix']}xxx): {r['available']} available / {r['in_use']} in-use / {r['total']} total")
    if errors:
      plain_lines += ["", "Errors:"] + [f"  {e}" for e in errors]
    plain_body = "\n".join(plain_lines)

    recipient = cfg["recipient"]
    recipient_2 = cfg["recipient_2"]
    recipients = [r for r in [recipient, recipient_2] if r]
    if not recipients:
      raise RuntimeError("No recipients configured for DN availability report.")
    sender = cfg["from_address"] or "noreply@amnhealthcare.com"

    _send_smtp_email(sender=sender, recipients=recipients, subject=subject, body=plain_body, html_body=html_body)

    summary_parts = "|".join(f"{r['label']}:{r['available']}" for r in results)
    _append_audit_event(
      action="dn_avail_report_sent",
      cucm_host=cucm_host,
      operator=triggered_by,
      target=f"run_at={run_at};summary={summary_parts}",
      account="|".join(recipients),
      extension_added="",
      extension_deleted="",
      output_filename=f"dn_avail_report_{run_at[:10].replace('-','')}.html",
      inline_mode=False,
    )

    return {
      "success": True,
      "run_at": run_at,
      "recipients": recipients,
      "results": results,
      "errors": errors,
    }
  except Exception as exc:
    logger.error("dn_availability_report failed: %s", exc, exc_info=True)
    return {"success": False, "error": str(exc)}


def _dn_report_scheduler_loop():
  """Daemon thread: fires _run_dn_availability_report at the configured PST time."""
  tz = ZoneInfo("America/Los_Angeles")
  while True:
    try:
      time.sleep(60)
      cfg = _get_dn_report_settings()
      if not cfg["enabled"]:
        continue
      now = datetime.datetime.now(tz=tz)
      if now.hour != cfg["hour"] or now.minute != cfg["minute"]:
        continue
      if cfg["frequency"] == "weekly":
        # simple weekly: only fire on Monday (or extend later)
        if now.weekday() != 0:
          continue
      fire_key = now.strftime("%Y-%m-%d")
      with _DN_REPORT_SCHEDULER_LOCK:
        if _DN_REPORT_SCHEDULER_LAST_FIRED.get("last") == fire_key:
          continue
        _DN_REPORT_SCHEDULER_LAST_FIRED["last"] = fire_key
      logger.info("dn_avail_report: firing for key=%s", fire_key)
      result = _run_dn_availability_report(triggered_by="scheduler")
      logger.info("dn_avail_report: result=%s", result)
    except Exception as exc:
      logger.error("dn_report_scheduler_loop error: %s", exc, exc_info=True)


_dn_report_thread = threading.Thread(target=_dn_report_scheduler_loop, name="dn-avail-report-scheduler", daemon=True)
_dn_report_thread.start()


def _ensure_twilio_sms_hosting_audit_log():
  os.makedirs(os.path.dirname(TWILIO_SMS_HOSTING_AUDIT_PATH), exist_ok=True)
  if os.path.exists(TWILIO_SMS_HOSTING_AUDIT_PATH):
    return

  with open(TWILIO_SMS_HOSTING_AUDIT_PATH, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow(TWILIO_SMS_HOSTING_AUDIT_FIELDS)


def _append_twilio_sms_hosting_audit_rows(rows: list[dict]):
  if not rows:
    return

  with TWILIO_SMS_HOSTING_AUDIT_LOCK:
    _ensure_twilio_sms_hosting_audit_log()
    _prune_twilio_sms_hosting_audit_locked()
    with open(TWILIO_SMS_HOSTING_AUDIT_PATH, "a", newline="", encoding="utf-8") as handle:
      writer = csv.DictWriter(handle, fieldnames=TWILIO_SMS_HOSTING_AUDIT_FIELDS)
      for row in rows:
        writer.writerow({field: row.get(field, "") for field in TWILIO_SMS_HOSTING_AUDIT_FIELDS})


def _prune_twilio_sms_hosting_audit_locked():
  _ensure_twilio_sms_hosting_audit_log()

  with open(TWILIO_SMS_HOSTING_AUDIT_PATH, "r", newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    rows = list(reader)

  cutoff = _audit_now() - datetime.timedelta(days=TWILIO_SMS_HOSTING_AUDIT_RETENTION_DAYS)
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

  with open(TWILIO_SMS_HOSTING_AUDIT_PATH, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=TWILIO_SMS_HOSTING_AUDIT_FIELDS)
    writer.writeheader()
    for row in kept_rows:
      writer.writerow({field: row.get(field, "") for field in TWILIO_SMS_HOSTING_AUDIT_FIELDS})


def _load_twilio_sms_hosting_audit_rows(limit: int | None = None) -> list[dict]:
  with TWILIO_SMS_HOSTING_AUDIT_LOCK:
    _ensure_twilio_sms_hosting_audit_log()
    _prune_twilio_sms_hosting_audit_locked()
    with open(TWILIO_SMS_HOSTING_AUDIT_PATH, "r", newline="", encoding="utf-8") as handle:
      rows = list(csv.DictReader(handle))

  rows = list(reversed(rows))
  if limit is not None and limit >= 0:
    rows = rows[:limit]
  return rows


def _append_strike_mask_history_event(
  event: str,
  operation_id: str,
  cucm_host: str,
  operator: str,
  target_user: str,
  translation_pattern: str,
  translation_pattern_partition: str,
  devices: list[dict],
  detail: str = "",
):
  os.makedirs(os.path.dirname(STRIKE_MASK_HISTORY_PATH), exist_ok=True)

  with STRIKE_MASK_HISTORY_LOCK:
    if not os.path.exists(STRIKE_MASK_HISTORY_PATH):
      with open(STRIKE_MASK_HISTORY_PATH, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(STRIKE_MASK_HISTORY_FIELDS)

    timestamp_text = _audit_now().strftime(AUDIT_TIMESTAMP_FORMAT)
    rows = []
    device_list = devices or [{}]
    for device in device_list:
      rows.append([
        timestamp_text,
        event,
        operation_id,
        cucm_host,
        operator,
        target_user,
        translation_pattern,
        translation_pattern_partition,
        device.get("device_name", "") or device.get("name", ""),
        device.get("device_type", "") or device.get("type", ""),
        device.get("line_mask_status", device.get("status", "")),
        detail,
      ])

    with open(STRIKE_MASK_HISTORY_PATH, "a", newline="", encoding="utf-8") as handle:
      writer = csv.writer(handle)
      writer.writerows(rows)


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
  html_body: str = "",
    smtp_user: str = "",
    smtp_pass: str = "",
    smtp_port: int | None = None,
    use_starttls: bool | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
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
    if (html_body or "").strip():
      message.add_alternative(html_body, subtype="html")
    for attachment in attachments or []:
      filename, content, mime_type = attachment
      maintype, subtype = (mime_type or "application/octet-stream").split("/", 1)
      message.add_attachment(_to_bytes(content), maintype=maintype, subtype=subtype, filename=filename)

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


def _derive_admin_audit_email(username: str) -> str:
  """Build recipient email from logged-in admin username by stripping .ad/.adm suffix."""
  clean_user = (username or "").strip()
  if not clean_user:
    return ""
  lowered = clean_user.lower()
  if lowered.endswith(".adm"):
    clean_user = clean_user[:-4]
  elif lowered.endswith(".ad"):
    clean_user = clean_user[:-3]
  clean_user = clean_user.strip()
  if not clean_user:
    return ""
  return f"{clean_user}@{AUDIT_LOG_EMAIL_DOMAIN}"


def _normalize_phone_to_e164(phone_number: str) -> str:
  raw = (phone_number or "").strip()
  if not raw:
    return ""
  digits = "".join(ch for ch in raw if ch.isdigit())
  if not digits:
    return ""
  if len(digits) == 11 and digits.startswith("1"):
    return f"+{digits}"
  if len(digits) == 10:
    return f"+1{digits}"
  return f"+{digits}" if not raw.startswith("+") else raw


def _resolve_twilio_lookup_account_sid() -> str:
  """Choose subaccount SID for lookup if configured, else use primary account SID."""
  if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
    return ""

  if TWILIO_SUBACCOUNT_SID:
    return TWILIO_SUBACCOUNT_SID

  if not TWILIO_SUBACCOUNT_NAME:
    return TWILIO_ACCOUNT_SID

  try:
    resp = requests.get(
      f"https://api.twilio.com/2010-04-01/Accounts.json",
      params={"FriendlyName": TWILIO_SUBACCOUNT_NAME, "Status": "active", "PageSize": 20},
      auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
      timeout=20,
    )
    if resp.status_code != 200:
      return TWILIO_ACCOUNT_SID
    payload = resp.json() if resp.text else {}
    for acct in payload.get("accounts", []) or []:
      if str(acct.get("friendly_name", "")).strip() == TWILIO_SUBACCOUNT_NAME:
        return str(acct.get("sid", "")).strip() or TWILIO_ACCOUNT_SID
  except Exception:
    pass

  return TWILIO_ACCOUNT_SID

def _resolve_twilio_salesforce_account_sid() -> str:
  """Choose Salesforce Enterprise Org Prod sub-account SID if configured."""
  if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
    return ""

  if TWILIO_SALESFORCE_SUBACCOUNT_SID:
    return TWILIO_SALESFORCE_SUBACCOUNT_SID

  if not TWILIO_SALESFORCE_SUBACCOUNT_NAME:
    return TWILIO_ACCOUNT_SID

  try:
    resp = requests.get(
      f"https://api.twilio.com/2010-04-01/Accounts.json",
      params={"FriendlyName": TWILIO_SALESFORCE_SUBACCOUNT_NAME, "Status": "active", "PageSize": 20},
      auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
      timeout=20,
    )
    if resp.status_code != 200:
      return TWILIO_ACCOUNT_SID
    payload = resp.json() if resp.text else {}
    for acct in payload.get("accounts", []) or []:
      if str(acct.get("friendly_name", "")).strip() == TWILIO_SALESFORCE_SUBACCOUNT_NAME:
        return str(acct.get("sid", "")).strip() or TWILIO_ACCOUNT_SID
  except Exception:
    pass

  return TWILIO_ACCOUNT_SID


def _resolve_twilio_lookup_auth_token_for_sid(account_sid: str) -> str:
  sid = (account_sid or "").strip()
  if sid and TWILIO_SUBACCOUNT_SID and sid == TWILIO_SUBACCOUNT_SID and TWILIO_SUBACCOUNT_AUTH_TOKEN:
    return TWILIO_SUBACCOUNT_AUTH_TOKEN
  return TWILIO_AUTH_TOKEN


def _list_twilio_incoming_phone_numbers(lookup_sid: str, lookup_token: str, force_refresh: bool = False) -> dict:
  if not lookup_sid or not lookup_token:
    return {"ok": False, "status": "Twilio account not configured", "numbers": []}

  try:
    cache_key = lookup_sid
    now = time.time()
    cached_numbers = []
    with TWILIO_INCOMING_PHONE_NUMBER_CACHE_LOCK:
      cache_entry = TWILIO_INCOMING_PHONE_NUMBER_CACHE.get(cache_key, {})
      cached_at = float(cache_entry.get("cached_at", 0) or 0)
      if (not force_refresh) and cached_at and (now - cached_at) < TWILIO_INCOMING_PHONE_NUMBER_CACHE_TTL_SECONDS:
        cached_numbers = list(cache_entry.get("numbers", []) or [])

    if not cached_numbers:
      cached_numbers = []
      next_url = f"https://api.twilio.com/2010-04-01/Accounts/{lookup_sid}/IncomingPhoneNumbers.json"
      next_params = {"PageSize": 100}
      while next_url:
        resp = requests.get(
          next_url,
          params=next_params,
          auth=(lookup_sid, lookup_token),
          verify=False,
          timeout=20,
        )
        if resp.status_code != 200:
          return {
            "ok": False,
            "status": f"Lookup failed HTTP {resp.status_code}",
            "numbers": [],
          }

        payload = resp.json() if resp.text else {}
        cached_numbers.extend(payload.get("incoming_phone_numbers", []) or [])

        next_uri = str(payload.get("next_page_uri", "") or "").strip()
        if next_uri:
          next_url = f"https://api.twilio.com{next_uri}" if next_uri.startswith("/") else next_uri
          next_params = None
        else:
          next_url = None

      with TWILIO_INCOMING_PHONE_NUMBER_CACHE_LOCK:
        TWILIO_INCOMING_PHONE_NUMBER_CACHE[cache_key] = {
          "cached_at": now,
          "numbers": cached_numbers,
        }

    return {"ok": True, "status": "OK", "numbers": cached_numbers}
  except Exception as exc:
    return {"ok": False, "status": f"Lookup error: {exc}", "numbers": []}


def _get_twilio_next_friendly_name_seed(account: str = "default") -> dict:
  if account == "salesforce":
    lookup_sid = _resolve_twilio_salesforce_account_sid()
    lookup_token = TWILIO_SALESFORCE_AUTH_TOKEN or TWILIO_AUTH_TOKEN
  else:
    lookup_sid = _resolve_twilio_lookup_account_sid()
    lookup_token = _resolve_twilio_lookup_auth_token_for_sid(lookup_sid)

  if not lookup_sid or not lookup_token:
    return {"ok": False, "status": "Twilio account not configured", "date_prefix": "", "next_index": 1}

  try:
    now_dt = datetime.datetime.now(ZoneInfo(AUDIT_TIMEZONE))
  except Exception:
    now_dt = datetime.datetime.now()
  date_prefix = now_dt.strftime("%Y%m%d")

  listed = _list_twilio_incoming_phone_numbers(lookup_sid, lookup_token, force_refresh=True)
  if not listed.get("ok"):
    return {
      "ok": False,
      "status": str(listed.get("status", "Unable to list Twilio numbers")),
      "date_prefix": date_prefix,
      "next_index": 1,
    }

  pattern = re.compile(rf"^{re.escape(date_prefix)}_(\d+)$")
  max_index = 0
  for item in listed.get("numbers", []) or []:
    if not isinstance(item, dict):
      continue
    friendly = str(item.get("friendly_name", "") or "").strip()
    match = pattern.match(friendly)
    if not match:
      continue
    try:
      max_index = max(max_index, int(match.group(1)))
    except Exception:
      continue

  return {"ok": True, "status": "OK", "date_prefix": date_prefix, "next_index": max_index + 1}


def _lookup_twilio_number_by_phone(phone_number: str, account: str = "default", force_refresh: bool = False) -> dict:
  """Lookup Twilio IncomingPhoneNumbers by phone number; returns sid/number if found.
  
  Args:
    phone_number: The phone number to lookup
    account: Which account to query - "default" (AMIEWeb) or "salesforce" (Enterprise Org Prod)
  """
  e164 = _normalize_phone_to_e164(phone_number)
  configured_account_name = TWILIO_SALESFORCE_SUBACCOUNT_NAME if account == "salesforce" else TWILIO_SUBACCOUNT_NAME
  if not e164:
    return {
      "enabled": bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN),
      "found": False,
      "phone_number": "",
      "sid": "",
      "lookup_account_name": configured_account_name,
      "lookup_account_sid": "",
      "status": "No telephone",
    }

  if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
    return {
      "enabled": False,
      "found": False,
      "phone_number": e164,
      "sid": "",
      "lookup_account_name": configured_account_name,
      "lookup_account_sid": "",
      "status": "Twilio credentials not configured",
    }

  # Determine primary account SID/token for this lookup context.
  if account == "salesforce":
    lookup_sid = _resolve_twilio_salesforce_account_sid()
    lookup_token = TWILIO_SALESFORCE_AUTH_TOKEN or TWILIO_AUTH_TOKEN
  else:
    lookup_sid = _resolve_twilio_lookup_account_sid()
    lookup_token = _resolve_twilio_lookup_auth_token_for_sid(lookup_sid)
    
  if not lookup_sid:
    return {
      "enabled": False,
      "found": False,
      "phone_number": e164,
      "sid": "",
      "lookup_account_name": configured_account_name,
      "lookup_account_sid": "",
      "status": "Twilio account not configured",
    }

  try:
    lookup_accounts: list[tuple[str, str, str]] = [(lookup_sid, lookup_token, configured_account_name or "Configured subaccount")]
    # Fallback to parent account search in case the number lives there.
    if (
      TWILIO_ACCOUNT_SID
      and TWILIO_AUTH_TOKEN
      and TWILIO_ACCOUNT_SID != lookup_sid
    ):
      lookup_accounts.append((TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, "Parent account"))

    phone_number_digits = "".join(ch for ch in e164 if ch.isdigit())
    candidates = {e164, phone_number_digits}
    if len(phone_number_digits) == 11 and phone_number_digits.startswith("1"):
      candidates.add(phone_number_digits[1:])
      candidates.add(f"+{phone_number_digits[1:]}")

    lookup_failures = []
    for account_sid, account_token, account_name in lookup_accounts:
      listed = _list_twilio_incoming_phone_numbers(account_sid, account_token, force_refresh=force_refresh)
      if not listed.get("ok"):
        lookup_failures.append(str(listed.get("status", "Lookup failed")))
        continue

      for number_item in listed.get("numbers", []) or []:
        if not isinstance(number_item, dict):
          continue
        candidate = str(number_item.get("phone_number", "")).strip()
        candidate_digits = "".join(ch for ch in candidate if ch.isdigit())
        if candidate in candidates or candidate_digits in candidates:
          return {
            "enabled": True,
            "found": True,
            "phone_number": candidate or e164,
            "sid": str(number_item.get("sid", "")).strip(),
            "lookup_account_name": account_name,
            "lookup_account_sid": account_sid,
            "lookup_auth_token": account_token,
            "status": "Found",
          }

    not_found_payload = {
      "enabled": True,
      "found": False,
      "phone_number": e164,
      "sid": "",
      "lookup_account_name": configured_account_name,
      "lookup_account_sid": lookup_sid,
      "status": "Not Found" if not lookup_failures else f"Not Found ({'; '.join(lookup_failures)})",
    }

    if not force_refresh:
      return _lookup_twilio_number_by_phone(phone_number, account=account, force_refresh=True)

    return not_found_payload
  except Exception as exc:
    return {
      "enabled": True,
      "found": False,
      "phone_number": e164,
      "sid": "",
      "lookup_account_name": configured_account_name,
      "lookup_account_sid": lookup_sid,
      "status": f"Lookup error: {exc}",
    }


def _parse_phone_number_input_list(raw_text: str) -> list[str]:
  values = []
  seen = set()
  for token in re.split(r"[\s,;]+", (raw_text or "").strip()):
    clean = (token or "").strip()
    if not clean:
      continue
    normalized = _normalize_phone_to_e164(clean)
    key = normalized or clean
    if key in seen:
      continue
    seen.add(key)
    values.append(clean)
  return values


def _lookup_twilio_number_in_subaccount(phone_number: str, force_refresh: bool = True) -> dict:
  e164 = _normalize_phone_to_e164(phone_number)
  if not e164:
    return {
      "enabled": bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN),
      "found": False,
      "phone_number": "",
      "sid": "",
      "lookup_account_sid": "",
      "lookup_auth_token": "",
      "status": "No telephone",
    }

  lookup_sid = _resolve_twilio_lookup_account_sid()
  lookup_token = _resolve_twilio_lookup_auth_token_for_sid(lookup_sid)
  if not lookup_sid or not lookup_token:
    return {
      "enabled": False,
      "found": False,
      "phone_number": e164,
      "sid": "",
      "lookup_account_sid": "",
      "lookup_auth_token": "",
      "status": "Twilio subaccount is not configured",
    }

  # Enforce subaccount-only behavior for hosting flow.
  if TWILIO_ACCOUNT_SID and lookup_sid == TWILIO_ACCOUNT_SID:
    return {
      "enabled": False,
      "found": False,
      "phone_number": e164,
      "sid": "",
      "lookup_account_sid": "",
      "lookup_auth_token": "",
      "status": "Twilio subaccount SID is required; parent account is not allowed for hosting",
    }

  listed = _list_twilio_incoming_phone_numbers(lookup_sid, lookup_token, force_refresh=force_refresh)
  if not listed.get("ok"):
    return {
      "enabled": True,
      "found": False,
      "phone_number": e164,
      "sid": "",
      "lookup_account_sid": lookup_sid,
      "lookup_auth_token": lookup_token,
      "status": str(listed.get("status", "Lookup failed")),
    }

  digits = "".join(ch for ch in e164 if ch.isdigit())
  candidates = {e164, digits}
  if len(digits) == 11 and digits.startswith("1"):
    candidates.add(digits[1:])
    candidates.add(f"+{digits[1:]}")

  for number_item in listed.get("numbers", []) or []:
    if not isinstance(number_item, dict):
      continue
    candidate = str(number_item.get("phone_number", "")).strip()
    candidate_digits = "".join(ch for ch in candidate if ch.isdigit())
    if candidate in candidates or candidate_digits in candidates:
      return {
        "enabled": True,
        "found": True,
        "phone_number": candidate or e164,
        "sid": str(number_item.get("sid", "") or "").strip(),
        "lookup_account_sid": lookup_sid,
        "lookup_auth_token": lookup_token,
        "status": "Found",
      }

  return {
    "enabled": True,
    "found": False,
    "phone_number": e164,
    "sid": "",
    "lookup_account_sid": lookup_sid,
    "lookup_auth_token": lookup_token,
    "status": "Not Found",
  }


def _build_twilio_sms_only_update_payload(
  sms_url: str,
  sms_method: str,
  sms_fallback_url: str,
  sms_fallback_method: str,
  status_callback_url: str,
  status_callback_method: str,
  friendly_name: str,
) -> dict:
  payload = {
    "SmsUrl": (sms_url or "").strip(),
    "SmsMethod": "POST" if (sms_method or "").strip().upper() not in {"GET", "POST"} else (sms_method or "").strip().upper(),
  }

  fallback_url = (sms_fallback_url or "").strip()
  if fallback_url:
    payload["SmsFallbackUrl"] = fallback_url
    payload["SmsFallbackMethod"] = "POST" if (sms_fallback_method or "").strip().upper() not in {"GET", "POST"} else (sms_fallback_method or "").strip().upper()

  callback_url = (status_callback_url or "").strip()
  if callback_url:
    payload["StatusCallback"] = callback_url
    payload["StatusCallbackMethod"] = "POST" if (status_callback_method or "").strip().upper() not in {"GET", "POST"} else (status_callback_method or "").strip().upper()

  clean_friendly_name = (friendly_name or "").strip()
  if clean_friendly_name:
    payload["FriendlyName"] = clean_friendly_name

  return payload


def _extract_twilio_verification_code(body: dict) -> str:
  if not isinstance(body, dict):
    return ""

  # Twilio responses may vary in casing/shape across APIs.
  direct_keys = [
    "verification_code",
    "verificationCode",
    "VerificationCode",
    "verificationcode",
  ]
  for key in direct_keys:
    value = str(body.get(key, "") or "").strip()
    if value:
      return value

  nested = body.get("verification", {})
  if isinstance(nested, dict):
    for key in ("code", "verification_code", "verificationCode"):
      value = str(nested.get(key, "") or "").strip()
      if value:
        return value

  return ""


def _twilio_update_sms_only_for_number(
  phone_number: str,
  payload: dict,
  loa_recipient_name: str = "",
  loa_recipient_email: str = "",
  loa_recipient_phone: str = "",
  loa_mode: str = "single",
  loa_batch_reference: str = "",
) -> dict:
  lookup = _lookup_twilio_number_in_subaccount(phone_number, force_refresh=True)
  if not lookup.get("enabled"):
    return {
      "ok": False,
      "input": phone_number,
      "normalized": _normalize_phone_to_e164(phone_number),
      "sid": "",
      "status": lookup.get("status", "Twilio is not configured"),
    }

  if not lookup.get("found") or not (lookup.get("sid") or "").strip():
    return _twilio_add_sms_hosted_number(
      phone_number,
      payload,
      str(lookup.get("status", "Not Found")),
      loa_recipient_name=loa_recipient_name,
      loa_recipient_email=loa_recipient_email,
      loa_recipient_phone=loa_recipient_phone,
      loa_mode=loa_mode,
      loa_batch_reference=loa_batch_reference,
    )

  lookup_sid = str(lookup.get("lookup_account_sid", "") or _resolve_twilio_lookup_account_sid())
  lookup_token = str(lookup.get("lookup_auth_token", "") or _resolve_twilio_lookup_auth_token_for_sid(lookup_sid))
  if not lookup_sid:
    return {
      "ok": False,
      "input": phone_number,
      "normalized": _normalize_phone_to_e164(phone_number),
      "sid": "",
      "status": "Twilio AMIEWeb account SID could not be resolved",
    }

  phone_sid = (lookup.get("sid") or "").strip()
  try:
    response = requests.post(
      f"https://api.twilio.com/2010-04-01/Accounts/{lookup_sid}/IncomingPhoneNumbers/{phone_sid}.json",
      data=payload,
      auth=(lookup_sid, lookup_token),
      verify=False,
      timeout=20,
    )
    body = response.json() if response.text else {}
    if response.status_code not in {200, 201}:
      err_message = str(body.get("message", "")).strip() or f"Twilio update failed HTTP {response.status_code}"
      return {
        "ok": False,
        "input": phone_number,
        "normalized": _normalize_phone_to_e164(phone_number),
        "sid": phone_sid,
        "status": err_message,
      }

    with TWILIO_INCOMING_PHONE_NUMBER_CACHE_LOCK:
      TWILIO_INCOMING_PHONE_NUMBER_CACHE.pop(lookup_sid, None)

    return {
      "ok": True,
      "action": "Updated",
      "input": phone_number,
      "normalized": _normalize_phone_to_e164(phone_number),
      "twilio_number": (body.get("phone_number") or lookup.get("phone_number") or "").strip(),
      "sid": phone_sid,
      "friendly_name": str(body.get("friendly_name", "") or payload.get("FriendlyName", "")).strip(),
      "verification_code": _extract_twilio_verification_code(body),
      "sms_url": str(body.get("sms_url", "") or "").strip(),
      "sms_method": str(body.get("sms_method", "") or "").strip(),
      "status_callback": str(body.get("status_callback", "") or "").strip(),
      "messaging_service_sid": TWILIO_AMIEWEB_MESSAGING_SERVICE_SID,
      "messaging_service_status": "Already hosted; no messaging-service attach required",
      "status": "Updated",
    }
  except Exception as exc:
    return {
      "ok": False,
      "action": "Failed",
      "input": phone_number,
      "normalized": _normalize_phone_to_e164(phone_number),
      "sid": phone_sid,
      "status": f"Twilio update error: {exc}",
    }


def _twilio_attach_phone_to_messaging_service(
  account_sid: str,
  account_token: str,
  phone_sid: str,
) -> tuple[bool, str]:
  if not TWILIO_AMIEWEB_MESSAGING_SERVICE_SID:
    return False, "Messaging Service SID is not configured"
  if not phone_sid:
    return False, "Phone SID is required for Messaging Service registration"

  try:
    response = requests.post(
      f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messaging/Services/{TWILIO_AMIEWEB_MESSAGING_SERVICE_SID}/PhoneNumbers.json",
      data={"PhoneNumberSid": phone_sid},
      auth=(account_sid, account_token),
      verify=False,
      timeout=20,
    )
    body = response.json() if response.text else {}
    if response.status_code in {200, 201}:
      return True, "Registered"

    message = str(body.get("message", "") or "").strip()
    if "already" in message.lower() and "service" in message.lower():
      return True, "Already registered"
    return False, message or f"Messaging Service attach failed HTTP {response.status_code}"
  except Exception as exc:
    return False, f"Messaging Service attach error: {exc}"


def _twilio_add_sms_hosted_number(
  phone_number: str,
  payload: dict,
  lookup_status: str = "",
  loa_recipient_name: str = "",
  loa_recipient_email: str = "",
  loa_recipient_phone: str = "",
  loa_mode: str = "single",
  loa_batch_reference: str = "",
) -> dict:
  normalized = _normalize_phone_to_e164(phone_number)
  primary_sid = _resolve_twilio_lookup_account_sid()
  primary_token = _resolve_twilio_lookup_auth_token_for_sid(primary_sid)
  if not primary_sid or not primary_token:
    return {
      "ok": False,
      "action": "Failed",
      "input": phone_number,
      "normalized": normalized,
      "sid": "",
      "status": "Twilio AMIEWeb account is not configured for add/provision",
    }

  if TWILIO_ACCOUNT_SID and primary_sid == TWILIO_ACCOUNT_SID:
    return {
      "ok": False,
      "action": "Failed",
      "input": phone_number,
      "normalized": normalized,
      "sid": "",
      "status": "Twilio subaccount SID is required; parent account is not allowed for hosting",
    }

  create_payload = {
    "PhoneNumber": normalized,
    "SmsCapability": "true",
  }
  clean_friendly = str(payload.get("FriendlyName", "") or "").strip()
  if clean_friendly:
    create_payload["FriendlyName"] = clean_friendly
  status_callback_url = str(payload.get("StatusCallback", "") or "").strip()
  if status_callback_url:
    create_payload["StatusCallbackUrl"] = status_callback_url
    create_payload["StatusCallbackMethod"] = str(payload.get("StatusCallbackMethod", "POST") or "POST").strip().upper()
  if loa_recipient_email:
    create_payload["Email"] = loa_recipient_email
  if loa_batch_reference:
    create_payload["UniqueName"] = loa_batch_reference

  attempt_errors = []
  hosted_order_endpoints = [
    "https://preview.twilio.com/HostedNumbers/HostedNumberOrders",
    "https://preview.twilio.com/HostedNumbers/HostedNumberOrders.json",
    f"https://api.twilio.com/2010-04-01/Accounts/{primary_sid}/IncomingPhoneNumbers/HostedNumberOrders.json",
    f"https://api.twilio.com/2010-04-01/Accounts/{primary_sid}/IncomingPhoneNumbers/HostedNumberOrders",
    "https://api.twilio.com/2010-04-01/IncomingPhoneNumbers/HostedNumberOrders.json",
    "https://api.twilio.com/2010-04-01/IncomingPhoneNumbers/HostedNumberOrders",
  ]
  auth_attempts = [(primary_sid, primary_token, "subaccount", False)]
  if (
    TWILIO_ACCOUNT_SID
    and TWILIO_AUTH_TOKEN
    and TWILIO_ACCOUNT_SID != primary_sid
  ):
    auth_attempts.append((TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, "parent-account", True))

  for auth_sid, auth_token, auth_label, include_account_sid in auth_attempts:
    for endpoint in hosted_order_endpoints:
      try:
        request_payload = dict(create_payload)
        if include_account_sid:
          request_payload["AccountSid"] = primary_sid

        response = requests.post(
          endpoint,
          data=request_payload,
          auth=(auth_sid, auth_token),
          verify=False,
          timeout=20,
        )

        body = {}
        if response.text:
          try:
            body = response.json()
          except Exception:
            body = {}

        if response.status_code in {200, 201}:
          order_sid = str(body.get("sid", "") or body.get("Sid", "") or "").strip()
          order_status = str(body.get("status", "") or body.get("Status", "") or "Pending").strip()
          verification_code = _extract_twilio_verification_code(body)

          return {
            "ok": True,
            "action": "HostedOrderCreated",
            "input": phone_number,
            "normalized": normalized,
            "twilio_number": normalized,
            "sid": order_sid,
            "friendly_name": clean_friendly,
            "verification_code": verification_code,
            "sms_url": str(payload.get("SmsUrl", "") or "").strip(),
            "sms_method": str(payload.get("SmsMethod", "") or "").strip(),
            "status_callback": str(payload.get("StatusCallback", "") or "").strip(),
            "loa_recipient_name": loa_recipient_name,
            "loa_recipient_email": loa_recipient_email,
            "loa_recipient_phone": loa_recipient_phone,
            "loa_mode": loa_mode,
            "loa_batch_reference": loa_batch_reference,
            "messaging_service_sid": TWILIO_AMIEWEB_MESSAGING_SERVICE_SID,
            "messaging_service_status": "Pending number completion before registration",
            "status": f"Hosted order created ({order_status})",
          }

        err_message = str(body.get("message", "") or body.get("Message", "")).strip()
        if not err_message:
          raw_message = (response.text or "").strip().replace("\r", " ").replace("\n", " ")
          err_message = raw_message[:240] if raw_message else f"Hosted order create failed HTTP {response.status_code}"
        attempt_errors.append(f"AMIEWeb {auth_label} [{endpoint}]: {err_message}")
      except Exception as exc:
        attempt_errors.append(f"AMIEWeb {auth_label} [{endpoint}]: Hosted order create error: {exc}")

  prefix = f"{lookup_status}; " if lookup_status else ""
  errors_joined = " | ".join(attempt_errors)
  lower_errors = errors_joined.lower()
  sub_preview_not_found = (
    "amieweb subaccount [https://preview.twilio.com/hostednumbers/hostednumberorders]" in lower_errors
    and "requested resource /hostednumbers/hostednumberorders was not found" in lower_errors
  )
  parent_auth_failed = (
    "amieweb parent-account" in lower_errors
    and ("authenticate" in lower_errors or "`20003`" in lower_errors)
  )

  concise_status = ""
  if sub_preview_not_found:
    concise_status = "Hosted Number create blocked: Twilio Hosted Numbers Developer Preview is not enabled for the AMIEWeb subaccount or account context."
    if parent_auth_failed:
      concise_status += " Parent-account fallback auth also failed (20003)."
    concise_status += " Next: enable Hosted Numbers preview for this account path in Twilio, then retry one number."

  final_status = f"{prefix}{concise_status}" if concise_status else f"{prefix}{errors_joined}"
  return {
    "ok": False,
    "action": "Failed",
    "input": phone_number,
    "normalized": normalized,
    "sid": "",
    "status": final_status,
  }


def _store_job_output(data_bytes: bytes, filename: str, media_type: str = "text/csv") -> str:
    job_id = str(uuid4())
    JOB_OUTPUTS[job_id] = {"data": data_bytes, "filename": filename, "media_type": media_type}

    # Keep an in-memory cap so older outputs naturally roll off.
    if len(JOB_OUTPUTS) > 100:
        oldest_key = next(iter(JOB_OUTPUTS))
        JOB_OUTPUTS.pop(oldest_key, None)

    return job_id


def _prepare_job_output(csv_data, filename: str) -> dict:
    csv_bytes = _to_bytes(csv_data)
    job_id = _store_job_output(csv_bytes, filename, "text/csv")
    return {
        "job_id": job_id,
        "filename": filename,
        "output_text": csv_bytes.decode("utf-8", errors="replace"),
    }


def _lookup_aerialink_account_code_by_phone(phone_number: str) -> dict:
  """Lookup whether the number is provisioned in Aerialink account code inventory."""
  e164 = _normalize_phone_to_e164(phone_number)
  if not e164:
    return {
      "enabled": bool(AERIALINK_V5_BASE_URL and AERIALINK_USERNAME and AERIALINK_PASSWORD),
      "found": False,
      "provisioned": False,
      "requested_number": "",
      "matched_number": "",
      "status": "No telephone",
    }

  if INTEGRATION_PREFLIGHT_REQUIRED:
    preflight = _check_aerialink_feasibility()
    if not preflight.get("ok"):
      return {
        "enabled": True,
        "found": False,
        "provisioned": False,
        "requested_number": e164,
        "matched_number": "",
        "status": _build_lookup_error("Aerialink lookup", str(preflight.get("status", "Preflight failed")), str(preflight.get("hint", ""))),
      }

  if not AERIALINK_V5_BASE_URL:
    return {
      "enabled": False,
      "found": False,
      "provisioned": False,
      "requested_number": e164,
      "matched_number": "",
      "status": _build_lookup_error("Aerialink lookup", "Aerialink base URL not configured", "Set AERIALINK_V5_BASE_URL in environment settings."),
    }

  if not AERIALINK_USERNAME or not AERIALINK_PASSWORD:
    return {
      "enabled": False,
      "found": False,
      "provisioned": False,
      "requested_number": e164,
      "matched_number": "",
      "status": _build_lookup_error("Aerialink lookup", "Aerialink credentials not configured", "Set AERIALINK_USERNAME and AERIALINK_PASSWORD in environment settings."),
    }

  endpoint_path = AERIALINK_ACCOUNT_CODE_LOOKUP_PATH or "/codes"
  endpoint_path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
  url = f"{AERIALINK_V5_BASE_URL}{endpoint_path}"

  number_digits = "".join(ch for ch in e164 if ch.isdigit())
  candidates = {e164, number_digits}
  if len(number_digits) == 11 and number_digits.startswith("1"):
    candidates.add(number_digits[1:])
    candidates.add(f"+{number_digits[1:]}")

  try:
    response = requests.get(
      url,
      params={"codes": number_digits},
      headers={"Accept": "application/json"},
      auth=HTTPBasicAuth(AERIALINK_USERNAME, AERIALINK_PASSWORD),
      verify=False,
      timeout=25,
    )
    if response.status_code != 200:
      return {
        "enabled": True,
        "found": False,
        "provisioned": False,
        "requested_number": e164,
        "matched_number": "",
        "status": _build_lookup_error("Aerialink lookup", f"HTTP {response.status_code}", "Verify endpoint path, credentials, and network egress from this host."),
      }

    payload = response.json() if response.text else {}
    records = []
    if isinstance(payload, list):
      records = payload
    elif isinstance(payload, dict):
      for key in ["codes", "data", "results", "items"]:
        value = payload.get(key)
        if isinstance(value, list):
          records = value
          break

    matched = ""
    for record in records:
      if not isinstance(record, dict):
        continue
      for field in ["code", "phoneNumber", "phone_number", "number", "msisdn"]:
        candidate = str(record.get(field) or "").strip()
        if not candidate:
          continue
        candidate_digits = "".join(ch for ch in candidate if ch.isdigit())
        if candidate in candidates or candidate_digits in candidates:
          matched = candidate
          break
      if matched:
        break

    if not records or not matched:
      return {
        "enabled": True,
        "found": False,
        "provisioned": False,
        "requested_number": e164,
        "matched_number": "",
        "status": "Not provisioned on Aerialink account",
      }

    return {
      "enabled": True,
      "found": True,
      "provisioned": True,
      "requested_number": e164,
      "matched_number": matched,
      "status": "Provisioned on Aerialink account",
    }
  except Exception as exc:
    return {
      "enabled": True,
      "found": False,
      "provisioned": False,
      "requested_number": e164,
      "matched_number": "",
      "status": _build_lookup_error("Aerialink lookup", str(exc), "Confirm DNS/network reachability and TLS policy from this host."),
    }


def _extract_soap_error(response_text: str) -> str:
  """Extract friendly error message from SOAP fault response, or return truncated text."""
  import re
  
  # If empty or very short, just truncate
  if not response_text or len(response_text) < 20:
    return response_text[:150]
  
  try:
    # Strategy 1: Find faultstring (with optional namespace prefix like soapenv:)
    match = re.search(r'<\w*:?faultstring[^>]*>([^<]+)<', response_text, re.IGNORECASE)
    if match:
      text = match.group(1).strip()
      if text and len(text) > 2:
        return text[:250]

    # Strategy 2: Extract nested CUCM AXL fault fields.
    faultcode_match = re.search(r'<\w*:?faultcode[^>]*>([^<]*)<', response_text, re.IGNORECASE)
    axlcode_match = re.search(r'<\w*:?axlcode[^>]*>([^<]*)<', response_text, re.IGNORECASE)
    axlmessage_match = re.search(r'<\w*:?axlmessage[^>]*>([^<]*)<', response_text, re.IGNORECASE)
    request_match = re.search(r'<\w*:?request[^>]*>([^<]*)<', response_text, re.IGNORECASE)

    faultcode = (faultcode_match.group(1).strip() if faultcode_match else "")
    axlcode = (axlcode_match.group(1).strip() if axlcode_match else "")
    axlmessage = (axlmessage_match.group(1).strip() if axlmessage_match else "")
    request_name = (request_match.group(1).strip() if request_match else "")

    if axlmessage:
      parts = [axlmessage]
      if axlcode:
        parts.append(f"AXL code {axlcode}")
      if request_name:
        parts.append(f"request {request_name}")
      return " | ".join(parts)[:250]

    if axlcode or request_name or faultcode:
      if request_name == "addTransPattern" and axlcode == "-1":
        return (
          "CUCM rejected addTransPattern (AXL code -1). "
          "Check route partition ENT_DEVICE_PT, called-party transformation mask 2481001, "
          "and AXL permissions for this account."
        )[:250]

      parts = []
      if request_name:
        parts.append(f"CUCM rejected {request_name}")
      else:
        parts.append("CUCM returned SOAP fault")
      if axlcode:
        parts.append(f"AXL code {axlcode}")
      if faultcode:
        parts.append(faultcode)
      return " | ".join(parts)[:250]

    # Strategy 3: Find any element with text content between tags (prefer longer content)
    matches = re.findall(r'<\w*:?\w+[^>]*>([^<]{15,})<', response_text)
    if matches:
      # Return the longest match (usually the most informative)
      longest = max(matches, key=len)
      if longest.strip():
        return longest.strip()[:250]

    # Strategy 4: Try basic XML parsing as last resort
    try:
      root = ET.fromstring(response_text)
      fault_data: dict[str, str] = {}
      for elem in root.iter():
        tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
        lowered_tag = tag.lower()
        if lowered_tag == 'faultstring' and elem.text and elem.text.strip():
          return elem.text.strip()[:250]
        if lowered_tag in {'faultcode', 'axlcode', 'axlmessage', 'request'}:
          fault_data[lowered_tag] = (elem.text or '').strip()

      if fault_data:
        request_name = fault_data.get('request', '')
        axlcode = fault_data.get('axlcode', '')
        axlmessage = fault_data.get('axlmessage', '')
        faultcode = fault_data.get('faultcode', '')
        if axlmessage:
          return axlmessage[:250]
        if request_name == 'addTransPattern' and axlcode == '-1':
          return (
            "CUCM rejected addTransPattern (AXL code -1). "
            "Check route partition ENT_DEVICE_PT, called-party transformation mask 2481001, "
            "and AXL permissions for this account."
          )[:250]
        parts = []
        if request_name:
          parts.append(f"CUCM rejected {request_name}")
        if axlcode:
          parts.append(f"AXL code {axlcode}")
        if faultcode:
          parts.append(faultcode)
        if parts:
          return " | ".join(parts)[:250]
    except Exception:
      pass

  except Exception:
    pass

  # Fallback: return a more user-friendly message if extraction fails
  if 'Fault' in response_text:
    return "CUCM returned SOAP fault. Check route partition, transform mask, and AXL permissions."

  # Last resort: truncate raw response
  return response_text[:150]


def _strip_invalid_xml_chars(text: str) -> str:
  """Remove XML-invalid control characters that can break ElementTree parsing."""
  if not text:
    return ""

  cleaned = []
  for ch in text:
    code = ord(ch)
    if (
      code == 0x9
      or code == 0xA
      or code == 0xD
      or 0x20 <= code <= 0xD7FF
      or 0xE000 <= code <= 0xFFFD
      or 0x10000 <= code <= 0x10FFFF
    ):
      cleaned.append(ch)
  return "".join(cleaned)


def _parse_xml_or_runtime_error(response_text: str, operation_label: str):
  """Parse XML defensively and return RuntimeError with context on failure."""
  try:
    return ET.fromstring(response_text)
  except ET.ParseError:
    cleaned = _strip_invalid_xml_chars(response_text or "")
    if cleaned != (response_text or ""):
      try:
        return ET.fromstring(cleaned)
      except ET.ParseError as exc:
        raise RuntimeError(f"{operation_label} returned malformed XML: {exc}") from exc

    raise RuntimeError(f"{operation_label} returned malformed XML")


def _build_add_translation_pattern_soap(
  pattern: str,
  description: str,
  route_partition: str,
  called_party_transform_mask: str,
) -> str:
  return f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:addTransPattern sequence=\"1\">
      <transPattern>
        <pattern>{xml_escape(pattern)}</pattern>
        <description>{xml_escape(description)}</description>
        <usage>Translation</usage>
        <routePartitionName>{xml_escape(route_partition)}</routePartitionName>
        <callingSearchSpaceName>Route_Internal_CSS</callingSearchSpaceName>
        <calledPartyTransformationMask>{xml_escape(called_party_transform_mask)}</calledPartyTransformationMask>
      </transPattern>
    </axl:addTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""


def _require_admin_session(request: Request) -> tuple[dict, str]:
  session = _get_auth_session(request)
  if not session:
    raise RuntimeError("Authentication required.")

  username = str(session.get("username", "") or "").strip()
  if not _is_admin_user(username):
    raise RuntimeError("Admin authorization required for this action.")

  return session, username


def _parse_verasmart_queue_rows(csv_text: str) -> list[dict]:
  if not (csv_text or "").strip():
    return []

  reader = csv.DictReader(io.StringIO(csv_text))
  rows: list[dict] = []
  for raw in reader:
    row = {str(k or "").strip().lower(): (v or "").strip() for k, v in (raw or {}).items()}
    record_key = row.get("record_key", "") or row.get("userid", "") or row.get("employee_id", "") or row.get("target_user", "")
    target_change = row.get("target_change", "") or row.get("action", "")
    note = row.get("note", "")
    if not record_key and not target_change and not note:
      continue
    rows.append(
      {
        "record_key": record_key,
        "target_change": target_change,
        "note": note,
        "status": "Pending",
        "error": "",
      }
    )

  return rows


def _store_verasmart_queue_run(operator: str, source_filename: str, rows: list[dict]) -> dict:
  run_id = str(uuid4())
  now_text = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  entry = {
    "run_id": run_id,
    "created_at": now_text,
    "operator": operator,
    "source_filename": source_filename,
    "mode": "LAB_SCAFFOLD_ONLY",
    "status": "Queued",
    "total_rows": len(rows),
    "pending_rows": len(rows),
    "in_progress_rows": 0,
    "done_rows": 0,
    "failed_rows": 0,
    "note": "LAB scaffold only. No VeraSMART write actions executed.",
    "rows_preview": rows[:25],
  }

  with VERASMART_QUEUE_LOCK:
    VERASMART_QUEUE_RUNS[run_id] = entry
    if len(VERASMART_QUEUE_RUNS) > VERASMART_QUEUE_MAX_RUNS:
      oldest_key = next(iter(VERASMART_QUEUE_RUNS))
      VERASMART_QUEUE_RUNS.pop(oldest_key, None)

  return entry


def _list_verasmart_queue_runs(limit: int = 10) -> list[dict]:
  with VERASMART_QUEUE_LOCK:
    runs = list(VERASMART_QUEUE_RUNS.values())
  runs.sort(key=lambda item: item.get("created_at", ""), reverse=True)
  return runs[: max(1, min(limit, 50))]


def _get_line_external_number_mask(cucm_host: str, cucm_user: str, cucm_pass: str, pattern: str, partition: str = "ENT_DEVICE_PT") -> str:
  session = requests.Session()
  session.verify = False
  session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

  soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getLine>
      <pattern>{xml_escape(pattern)}</pattern>
      <routePartitionName>{xml_escape(partition)}</routePartitionName>
      <returnedTags>
        <externalPhoneNumberMask/>
      </returnedTags>
    </axl:getLine>
  </soapenv:Body>
</soapenv:Envelope>"""

  response = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=soap.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response.status_code != 200:
    return pattern

  root = _parse_xml_or_runtime_error(response.text or "", "getLine")
  for elem in root.iter():
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    if tag == "externalPhoneNumberMask":
      return (elem.text or "").strip() or pattern

  return pattern


def _enrich_devices_with_original_masks(cucm_host: str, cucm_user: str, cucm_pass: str, devices: list[dict], jabber_extension: str) -> list[dict]:
  """Capture original external phone number mask from each device's DN before Strike Mask apply."""
  enriched = []
  for dev in devices:
    dev_copy = dev.copy()
    try:
      original_mask = _get_line_external_number_mask(cucm_host, cucm_user, cucm_pass, jabber_extension)
      dev_copy["original_external_number_mask"] = original_mask
    except Exception:
      dev_copy["original_external_number_mask"] = jabber_extension

    enriched.append(dev_copy)

  return enriched


def _find_jabber_extension(cucm_host: str, cucm_user: str, cucm_pass: str, target_user: str) -> tuple[str, list[dict]]:
  clean_target = (target_user or "").strip()
  if not clean_target:
    raise RuntimeError("target_user is required")

  session = requests.Session()
  session.verify = False
  session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

  soap = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getUser>
      <userid>{escape(clean_target)}</userid>
      <returnedTags>
        <primaryExtension>
          <pattern/>
        </primaryExtension>
        <associatedDevices>
          <device/>
        </associatedDevices>
      </returnedTags>
    </axl:getUser>
  </soapenv:Body>
</soapenv:Envelope>"""

  response = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=soap.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response.status_code != 200:
    raise RuntimeError(f"getUser failed: {response.status_code}")

  root = _parse_xml_or_runtime_error(response.text or "", "getUser")
  primary_ext = ""
  jabber_devices = []

  for elem in root.iter():
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

    if tag == "pattern" and primary_ext == "":
      primary_ext = (elem.text or "").strip()
    elif tag == "device":
      dev_name = (elem.text or "").strip()
      if dev_name and (dev_name.upper().startswith("CSF") or dev_name.upper().startswith("TCT") or dev_name.upper().startswith("BOT")):
        if dev_name.upper().startswith("CSF"):
          dev_type = "CSF (Jabber Laptop)"
        elif dev_name.upper().startswith("TCT"):
          dev_type = "TCT (Jabber iPhone)"
        else:
          dev_type = "BOT (Jabber Android)"
        jabber_devices.append({"name": dev_name, "type": dev_type})

  if not primary_ext:
    raise RuntimeError(f"{clean_target} has no primary extension (no Jabber built)")
  if not jabber_devices:
    raise RuntimeError(f"{clean_target} has no Jabber devices (CSF/TCT/BOT) assigned")

  return primary_ext, jabber_devices


def _find_available_945_patterns(cucm_host: str, cucm_user: str, cucm_pass: str) -> list[dict]:
  session = requests.Session()
  session.verify = False
  session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

  soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:listTransPattern sequence="1">
      <searchCriteria>
        <pattern>%</pattern>
      </searchCriteria>
      <returnedTags>
        <pattern/>
        <routePartitionName/>
        <description/>
        <calledPartyTransformationMask/>
      </returnedTags>
    </axl:listTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""

  response = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=soap.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response.status_code != 200:
    raise RuntimeError(f"listTransPattern failed: {response.status_code}")

  root = _parse_xml_or_runtime_error(response.text or "", "listTransPattern")
  patterns = []

  for elem in root.iter():
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    if tag != "transPattern":
      continue

    pattern = ""
    partition = ""
    desc = ""
    mask = ""

    for child in list(elem):
      child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
      text = (child.text or "").strip()
      if child_tag == "pattern":
        pattern = text
      elif child_tag == "routePartitionName":
        partition = text
      elif child_tag == "description":
        desc = text
      elif child_tag in {"calledPartyTransformationMask", "calledPartyTransformMask"}:
        mask = text

    desc_lower = (desc or "").strip().lower()
    expected_simple_desc = f"strike mask - {pattern}".lower()
    mask_clean = (mask or "").strip()
    is_available = (
      (
        desc_lower.startswith("strike mask -")
        or desc_lower == expected_simple_desc
      )
      and mask_clean == STRIKE_MASK_AVAILABLE_TRANSFORM_MASK
    )

    if pattern and is_available:
      patterns.append({
        "pattern": pattern,
        "partition": partition,
        "description": desc,
        "called_party_transform_mask": mask,
      })

  return patterns


def _list_in_use_strike_mask_patterns(cucm_host: str, cucm_user: str, cucm_pass: str) -> list[dict]:
  session = requests.Session()
  session.verify = False
  session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

  soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:axl="http://www.cisco.com/AXL/API/15.0">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:listTransPattern sequence="1">
      <searchCriteria>
        <pattern>%</pattern>
      </searchCriteria>
      <returnedTags>
        <pattern/>
        <routePartitionName/>
        <description/>
        <calledPartyTransformationMask/>
      </returnedTags>
    </axl:listTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""

  response = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=soap.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response.status_code != 200:
    raise RuntimeError(f"listTransPattern failed: {response.status_code}")

  root = ET.fromstring(response.text)
  patterns = []

  for elem in root.iter():
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    if tag != "transPattern":
      continue

    pattern = ""
    partition = ""
    desc = ""
    mask = ""

    for child in list(elem):
      child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
      text = (child.text or "").strip()
      if child_tag == "pattern":
        pattern = text
      elif child_tag == "routePartitionName":
        partition = text
      elif child_tag == "description":
        desc = text
      elif child_tag in {"calledPartyTransformationMask", "calledPartyTransformMask"}:
        mask = text

    desc_lower = (desc or "").strip().lower()
    expected_simple_desc = f"strike mask - {pattern}".lower()
    is_available = (
      (
        desc_lower.startswith("strike mask -")
        or desc_lower == expected_simple_desc
      )
      and (mask or "").strip() == STRIKE_MASK_AVAILABLE_TRANSFORM_MASK
    )

    if pattern and desc_lower.startswith("strike mask -") and not is_available:
      patterns.append(
        {
          "pattern": pattern,
          "partition": partition,
          "description": desc,
          "called_party_transform_mask": mask,
        }
      )

  patterns.sort(key=lambda item: (item.get("pattern") or ""))
  return patterns


def _store_strike_mask_operation(operator: str, cucm_host: str, target_user: str, target_user_display: str, jabber_extension: str, selected_devices: list[dict], trans_pattern: str, trans_partition: str, original_transform_mask: str, original_description: str) -> str:
  op_id = str(uuid4())
  now_text = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  entry = {
    "operation_id": op_id,
    "created_at": now_text,
    "operator": operator,
    "cucm_host": cucm_host,
    "target_user": target_user,
    "target_user_display": target_user_display,
    "jabber_extension": jabber_extension,
    "applied_devices": selected_devices,
    "translation_pattern": trans_pattern,
    "translation_pattern_partition": trans_partition,
    "original_transform_mask": original_transform_mask,
    "original_pattern_description": original_description,
    "status": "Active",
    "reversed_at": None,
  }

  with STRIKE_MASK_LOCK:
    STRIKE_MASK_OPERATIONS[op_id] = entry
    if len(STRIKE_MASK_OPERATIONS) > STRIKE_MASK_MAX_OPERATIONS:
      oldest_key = next(iter(STRIKE_MASK_OPERATIONS))
      STRIKE_MASK_OPERATIONS.pop(oldest_key, None)

  return op_id


def _list_active_strike_mask_operations(limit: int = 20) -> list[dict]:
  with STRIKE_MASK_LOCK:
    all_ops = list(STRIKE_MASK_OPERATIONS.values())
  active = [op for op in all_ops if op.get("status") == "Active"]
  active.sort(key=lambda x: x.get("created_at", ""), reverse=True)
  return active[:max(1, min(limit, 100))]


def _get_strike_mask_operation(op_id: str) -> dict:
  with STRIKE_MASK_LOCK:
    return STRIKE_MASK_OPERATIONS.get(op_id, {})


def _mark_strike_mask_reversed(op_id: str):
  with STRIKE_MASK_LOCK:
    if op_id in STRIKE_MASK_OPERATIONS:
      STRIKE_MASK_OPERATIONS[op_id]["status"] = "Reversed"
      STRIKE_MASK_OPERATIONS[op_id]["reversed_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _reverse_strike_mask_pattern(cucm_host: str, cucm_user: str, cucm_pass: str, op_id: str) -> dict:
  op = _get_strike_mask_operation(op_id)
  if not op:
    raise RuntimeError(f"Operation {op_id} not found")

  if op.get("status") == "Reversed":
    raise RuntimeError(f"Operation {op_id} has already been reversed")

  trans_pattern = op.get("translation_pattern", "")
  trans_partition = op.get("translation_pattern_partition", "")
  
  if not trans_pattern or not trans_partition:
    raise RuntimeError(f"Operation {op_id} missing pattern details")

  session = requests.Session()
  session.verify = False
  session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

  new_description = f"Strike Mask - {trans_pattern} Available"
  new_transform_mask = STRIKE_MASK_AVAILABLE_TRANSFORM_MASK

  soap_xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:updateTransPattern sequence=\"1\">
      <pattern>{xml_escape(trans_pattern)}</pattern>
      <routePartitionName>{xml_escape(trans_partition)}</routePartitionName>
      <description>{xml_escape(new_description)}</description>
      <calledPartyTransformationMask>{xml_escape(new_transform_mask)}</calledPartyTransformationMask>
    </axl:updateTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""

  response = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=soap_xml.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response.status_code != 200:
    raise RuntimeError(f"updateTransPattern failed HTTP {response.status_code}: {response.text[:800]}")

  devices_reverted = []
  jabber_ext = op.get("jabber_extension", "")
  applied_devices = op.get("applied_devices", [])

  for dev_info in applied_devices:
    dev_name = dev_info.get("name", "")
    original_external_mask = dev_info.get("original_external_number_mask", jabber_ext)
    original_device_e164_mask = dev_info.get("original_device_e164_mask", "") or jabber_ext

    if dev_name:
      try:
        soap_update_line = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:updateLine sequence=\"1\">
      <pattern>{xml_escape(jabber_ext)}</pattern>
      <routePartitionName>ENT_DEVICE_PT</routePartitionName>
      <externalPhoneNumberMask>{xml_escape(original_external_mask)}</externalPhoneNumberMask>
    </axl:updateLine>
  </soapenv:Body>
</soapenv:Envelope>"""

        response_line = session.post(
          f"https://{cucm_host}:8443/axl/",
          data=soap_update_line.encode("utf-8"),
          headers={"Content-Type": "text/xml"},
          verify=False,
          timeout=60,
        )
        if response_line.status_code == 200:
          line_restore_result = _update_device_line_e164_mask(
            session=session,
            cucm_host=cucm_host,
            device_name=dev_name,
            line_pattern=jabber_ext,
            line_partition="ENT_DEVICE_PT",
            new_mask=original_device_e164_mask,
          )

          devices_reverted.append({
            "device_name": dev_name,
            "restored_external_mask": original_external_mask,
            "restored_device_e164_mask": original_device_e164_mask,
            "line_mask_status": line_restore_result.get("status", "Failed"),
            "line_mask_error": line_restore_result.get("error", ""),
            "status": "Success" if line_restore_result.get("status") == "Success" else "Partial",
          })
        else:
          devices_reverted.append({
            "device_name": dev_name,
            "restored_external_mask": original_external_mask,
            "restored_device_e164_mask": original_device_e164_mask,
            "status": "Failed",
            "error": response_line.text[:200],
          })
      except Exception as e:
        devices_reverted.append({
          "device_name": dev_name,
          "restored_external_mask": original_external_mask,
          "restored_device_e164_mask": original_device_e164_mask,
          "status": "Error",
          "error": str(e)[:200],
        })

  _mark_strike_mask_reversed(op_id)

  return {
    "operation_id": op_id,
    "status": "Reversed",
    "target_user": op.get("target_user", ""),
    "jabber_extension": jabber_ext,
    "translation_pattern": trans_pattern,
    "translation_pattern_partition": trans_partition,
    "new_description": new_description,
    "new_transform_mask": new_transform_mask,
    "devices_reverted": devices_reverted,
    "reversed_at": _get_strike_mask_operation(op_id).get("reversed_at", ""),
  }


def _update_device_line_e164_mask(session: requests.Session, cucm_host: str, device_name: str, line_pattern: str, line_partition: str, new_mask: str) -> dict:
  get_phone_xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getPhone>
      <name>{xml_escape(device_name)}</name>
      <returnedTags>
        <lines>
          <line>
            <index/>
            <dirn>
              <pattern/>
              <routePartitionName/>
            </dirn>
            <e164Mask/>
          </line>
        </lines>
      </returnedTags>
    </axl:getPhone>
  </soapenv:Body>
</soapenv:Envelope>"""

  response_get = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=get_phone_xml.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response_get.status_code != 200:
    return {
      "status": "Failed",
      "error": f"getPhone failed HTTP {response_get.status_code}",
    }

  target_index = ""
  target_existing_e164 = ""
  root = ET.fromstring(response_get.text)
  for elem in root.iter():
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    if tag != "line":
      continue

    line_index = ""
    pattern_val = ""
    partition_val = ""
    existing_e164_val = ""

    for child in list(elem):
      child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
      if child_tag == "index":
        line_index = (child.text or "").strip()
      elif child_tag == "e164Mask":
        existing_e164_val = (child.text or "").strip()
      elif child_tag == "dirn":
        for grandchild in list(child):
          grand_tag = grandchild.tag.split("}")[-1] if "}" in grandchild.tag else grandchild.tag
          if grand_tag == "pattern":
            pattern_val = (grandchild.text or "").strip()
          elif grand_tag == "routePartitionName":
            partition_val = (grandchild.text or "").strip()

    if line_index and pattern_val == line_pattern and partition_val == line_partition:
      target_index = line_index
      target_existing_e164 = existing_e164_val
      break

  if not target_index:
    return {
      "status": "Failed",
      "error": f"No matching line appearance found on {device_name} for {line_pattern} ({line_partition})",
    }

  update_phone_xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:updatePhone sequence=\"1\">
      <name>{xml_escape(device_name)}</name>
      <lines>
        <line>
          <index>{xml_escape(target_index)}</index>
          <dirn>
            <pattern>{xml_escape(line_pattern)}</pattern>
            <routePartitionName>{xml_escape(line_partition)}</routePartitionName>
          </dirn>
          <e164Mask>{xml_escape(new_mask)}</e164Mask>
        </line>
      </lines>
    </axl:updatePhone>
  </soapenv:Body>
</soapenv:Envelope>"""

  response_update = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=update_phone_xml.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response_update.status_code != 200:
    return {
      "status": "Failed",
      "error": f"updatePhone failed HTTP {response_update.status_code}",
      "previous_e164_mask": target_existing_e164,
    }

  return {
    "status": "Success",
    "line_index": target_index,
    "previous_e164_mask": target_existing_e164,
  }


def _apply_strike_mask_pattern(cucm_host: str, cucm_user: str, cucm_pass: str, target_user: str, operator: str, selected_pattern: str = "", selected_device_names: list[str] | None = None) -> dict:
  clean_target = (target_user or "").strip()
  if not clean_target:
    raise RuntimeError("target_user is required")

  jabber_extension, jabber_devices = _find_jabber_extension(cucm_host, cucm_user, cucm_pass, clean_target)
  if not jabber_devices:
    raise RuntimeError(f"{clean_target} has no Jabber devices (CSF/TCT/BOT) assigned")

  selected_device_names = selected_device_names or []
  selected_device_set = {name.strip() for name in selected_device_names if (name or "").strip()}
  if selected_device_set:
    selected_jabber_devices = [d for d in jabber_devices if (d.get("name") or "").strip() in selected_device_set]
  else:
    selected_jabber_devices = list(jabber_devices)

  if not selected_jabber_devices:
    raise RuntimeError(f"No valid Jabber devices were selected for {clean_target}")

  available_patterns = _find_available_945_patterns(cucm_host, cucm_user, cucm_pass)
  if not available_patterns:
    raise RuntimeError("No available Strike Mask patterns were found")

  selected = None
  requested_pattern = (selected_pattern or "").strip()
  if requested_pattern:
    for pattern_item in available_patterns:
      if (pattern_item.get("pattern") or "").strip() == requested_pattern:
        selected = pattern_item
        break
    if not selected:
      raise RuntimeError(f"Requested Strike Mask pattern is not available: {requested_pattern}")
  else:
    available_patterns.sort(key=lambda item: (item.get("pattern") or ""))
    selected = available_patterns[0]

  trans_pattern = (selected.get("pattern") or "").strip()
  trans_partition = (selected.get("partition") or "").strip()
  if not trans_pattern or not trans_partition:
    raise RuntimeError("Selected Strike Mask pattern is missing pattern/partition details")

  original_description = (selected.get("description") or "").strip()
  original_transform_mask = (selected.get("called_party_transform_mask") or "").strip()
  if not original_transform_mask:
    original_transform_mask = STRIKE_MASK_AVAILABLE_TRANSFORM_MASK

  selected_devices = _enrich_devices_with_original_masks(cucm_host, cucm_user, cucm_pass, selected_jabber_devices, jabber_extension)

  session = requests.Session()
  session.verify = False
  session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

  new_description = f"Strike Mask - {clean_target} {jabber_extension}"
  new_transform_mask = jabber_extension
  update_pattern_xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:updateTransPattern sequence=\"1\">
      <pattern>{xml_escape(trans_pattern)}</pattern>
      <routePartitionName>{xml_escape(trans_partition)}</routePartitionName>
      <description>{xml_escape(new_description)}</description>
      <calledPartyTransformationMask>{xml_escape(new_transform_mask)}</calledPartyTransformationMask>
    </axl:updateTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""

  response = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=update_pattern_xml.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response.status_code != 200:
    raise RuntimeError(f"updateTransPattern failed HTTP {response.status_code}: {response.text[:800]}")

  update_line_xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:updateLine sequence=\"1\">
      <pattern>{xml_escape(jabber_extension)}</pattern>
      <routePartitionName>ENT_DEVICE_PT</routePartitionName>
      <externalPhoneNumberMask>{xml_escape(trans_pattern)}</externalPhoneNumberMask>
    </axl:updateLine>
  </soapenv:Body>
</soapenv:Envelope>"""

  response_line = session.post(
    f"https://{cucm_host}:8443/axl/",
    data=update_line_xml.encode("utf-8"),
    headers={"Content-Type": "text/xml"},
    verify=False,
    timeout=60,
  )
  if response_line.status_code != 200:
    raise RuntimeError(f"updateLine failed HTTP {response_line.status_code}: {response_line.text[:800]}")

  devices_applied = []
  for dev_info in selected_devices:
    dev_name = (dev_info.get("name") or "").strip()
    phone_line_result = _update_device_line_e164_mask(
      session=session,
      cucm_host=cucm_host,
      device_name=dev_name,
      line_pattern=jabber_extension,
      line_partition="ENT_DEVICE_PT",
      new_mask=trans_pattern,
    ) if dev_name else {"status": "Failed", "error": "Missing device name"}

    if dev_name:
      dev_info["original_device_e164_mask"] = phone_line_result.get("previous_e164_mask", "") or jabber_extension

    devices_applied.append(
      {
        "device_name": dev_name,
        "device_type": dev_info.get("type", ""),
        "original_external_mask": dev_info.get("original_external_number_mask", ""),
        "original_device_e164_mask": dev_info.get("original_device_e164_mask", ""),
        "new_external_mask": trans_pattern,
        "line_mask_status": phone_line_result.get("status", "Failed"),
        "line_mask_error": phone_line_result.get("error", ""),
        "status": "Success" if phone_line_result.get("status") == "Success" else "Partial",
      }
    )

  op_id = _store_strike_mask_operation(
    operator=operator,
    cucm_host=cucm_host,
    target_user=clean_target,
    target_user_display=clean_target,
    jabber_extension=jabber_extension,
    selected_devices=selected_devices,
    trans_pattern=trans_pattern,
    trans_partition=trans_partition,
    original_transform_mask=original_transform_mask,
    original_description=original_description,
  )

  return {
    "operation_id": op_id,
    "target_user": clean_target,
    "jabber_extension": jabber_extension,
    "translation_pattern": trans_pattern,
    "translation_pattern_partition": trans_partition,
    "new_description": new_description,
    "new_transform_mask": new_transform_mask,
    "devices_applied": devices_applied,
  }


def _load_audit_rows(limit: int | None = None) -> list[dict]:
  with AUDIT_LOG_LOCK:
    _ensure_audit_log()
    _prune_audit_log_locked()
    with open(AUDIT_LOG_PATH, "r", newline="", encoding="utf-8") as handle:
      rows = list(csv.DictReader(handle))

  rows = list(reversed(rows))
  if limit is not None and limit >= 0:
    rows = rows[:limit]
  return rows


def _build_jabber_precheck_warnings(result: dict) -> list[str]:
  warnings: list[str] = []
  if result.get("jabber_built"):
    device_name = (result.get("device_name") or "").strip() or "existing CSF device"
    extension = (result.get("extension") or "").strip()
    if extension:
      warnings.append(f"Existing Jabber device found: {device_name} on extension {extension}.")
    else:
      warnings.append(f"Existing Jabber device found: {device_name}.")

  voicemail_extension = (result.get("voicemail_extension") or "").strip()
  if voicemail_extension:
    warnings.append(f"Existing voicemail extension found: {voicemail_extension}.")

  return warnings


def _list_translation_patterns_by_description(cucm_host: str, cucm_user: str, cucm_pass: str, description_text: str) -> list[dict]:
    clean_description = (description_text or "").strip()
    if not clean_description:
      raise RuntimeError("Translation pattern description is required.")

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    soap_xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:listTransPattern sequence=\"1\">
      <searchCriteria>
        <description>%{xml_escape(clean_description)}%</description>
      </searchCriteria>
      <returnedTags>
        <pattern/>
        <routePartitionName/>
        <description/>
        <calledPartyTransformationMask/>
      </returnedTags>
    </axl:listTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""

    response = session.post(
      f"https://{cucm_host}:8443/axl/",
      data=soap_xml.encode("utf-8"),
      headers={"Content-Type": "text/xml"},
      verify=False,
      timeout=60,
    )
    if response.status_code != 200:
      raise RuntimeError(f"listTransPattern failed HTTP {response.status_code}: {response.text[:800]}")

    root = ET.fromstring(response.text)
    matches = []
    target_desc = clean_description.casefold()

    for elem in root.iter():
      if elem.tag.split("}")[-1] != "transPattern":
        continue

      values = {
        "pattern": "",
        "route_partition": "",
        "description": "",
        "called_party_transform_mask": "",
      }
      for child in list(elem):
        key = child.tag.split("}")[-1]
        text = (child.text or "").strip()
        if key == "pattern":
          values["pattern"] = text
        elif key == "routePartitionName":
          values["route_partition"] = text
        elif key == "description":
          values["description"] = text
        elif key in {"calledPartyTransformationMask", "calledPartyTransformMask"}:
          values["called_party_transform_mask"] = text

      if values["description"].casefold() == target_desc and values["pattern"]:
        matches.append(values)

    return matches


def _get_twilio_inbound_verification_profile(profile_key: str) -> dict:
    key = (profile_key or "").strip().lower()
    profile = TWILIO_INBOUND_VERIFICATION_PROFILES.get(key)
    if not profile:
      raise RuntimeError("Unknown Twilio inbound verification profile.")
    return {
      "key": key,
      "panel_label": profile.get("panel_label", ""),
      "description": profile.get("description", ""),
      "home_pattern": profile.get("home_pattern", ""),
    }


def _get_single_twilio_inbound_verification_pattern(
  cucm_host: str,
  cucm_user: str,
  cucm_pass: str,
  profile_key: str,
) -> dict:
    profile = _get_twilio_inbound_verification_profile(profile_key)
    matches = _list_translation_patterns_by_description(
      cucm_host,
      cucm_user,
      cucm_pass,
      profile.get("description", ""),
    )

    if not matches:
      raise RuntimeError(
        "No translation pattern found with description "
        f"'{profile.get('description', '')}'."
      )

    if len(matches) > 1:
      joined = ", ".join(
        f"{item.get('pattern', '')}/{item.get('route_partition', '')}" for item in matches
      )
      raise RuntimeError(
        "Multiple translation patterns matched the constant description; no changes made. "
        f"Matches: {joined}"
      )

    return matches[0]


def _update_twilio_inbound_verification_pattern(
  cucm_host: str,
  cucm_user: str,
  cucm_pass: str,
  new_pattern: str,
  profile_key: str,
) -> dict:
    target_pattern = (new_pattern or "").strip()
    if not target_pattern:
      raise RuntimeError("Target translation pattern is required.")

    profile = _get_twilio_inbound_verification_profile(profile_key)
    current = _get_single_twilio_inbound_verification_pattern(cucm_host, cucm_user, cucm_pass, profile_key)
    old_pattern = current.get("pattern", "")
    route_partition = current.get("route_partition", "")
    if not old_pattern or not route_partition:
      raise RuntimeError("Could not resolve current translation pattern and route partition.")

    if old_pattern == target_pattern:
      return {
        "profile_key": profile.get("key", ""),
        "panel_label": profile.get("panel_label", ""),
        "home_pattern": profile.get("home_pattern", ""),
        "changed": False,
        "old_pattern": old_pattern,
        "new_pattern": target_pattern,
        "route_partition": route_partition,
        "description": current.get("description", ""),
        "called_party_transform_mask": current.get("called_party_transform_mask", ""),
      }

    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth(cucm_user, cucm_pass)

    soap_xml = f"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:updateTransPattern sequence=\"1\">
      <pattern>{xml_escape(old_pattern)}</pattern>
      <routePartitionName>{xml_escape(route_partition)}</routePartitionName>
      <newPattern>{xml_escape(target_pattern)}</newPattern>
    </axl:updateTransPattern>
  </soapenv:Body>
</soapenv:Envelope>"""

    response = session.post(
      f"https://{cucm_host}:8443/axl/",
      data=soap_xml.encode("utf-8"),
      headers={"Content-Type": "text/xml"},
      verify=False,
      timeout=60,
    )
    if response.status_code != 200:
      raise RuntimeError(f"updateTransPattern failed HTTP {response.status_code}: {response.text[:800]}")

    updated = _get_single_twilio_inbound_verification_pattern(cucm_host, cucm_user, cucm_pass, profile_key)
    return {
      "profile_key": profile.get("key", ""),
      "panel_label": profile.get("panel_label", ""),
      "home_pattern": profile.get("home_pattern", ""),
      "changed": True,
      "old_pattern": old_pattern,
      "new_pattern": updated.get("pattern", target_pattern),
      "route_partition": updated.get("route_partition", route_partition),
      "description": updated.get("description", ""),
      "called_party_transform_mask": updated.get("called_party_transform_mask", ""),
    }


def _cancel_twilio_inbound_auto_restore(profile_key: str):
    key = (profile_key or "").strip().lower()
    with TWILIO_INBOUND_AUTO_RESTORE_LOCK:
      existing = TWILIO_INBOUND_AUTO_RESTORE_TIMERS.pop(key, None)
      timer = existing.get("timer") if isinstance(existing, dict) else None
      if timer:
        timer.cancel()


def _schedule_twilio_inbound_auto_restore(
  profile_key: str,
  cucm_host: str,
  cucm_user: str,
  cucm_pass: str,
) -> float:
    profile = _get_twilio_inbound_verification_profile(profile_key)
    key = profile.get("key", "")
    restore_at_epoch = time.time() + TWILIO_INBOUND_AUTO_RESTORE_SECONDS

    timer_ref = {"timer": None}

    def _run_auto_restore():
      try:
        _update_twilio_inbound_verification_pattern(
          cucm_host=cucm_host,
          cucm_user=cucm_user,
          cucm_pass=cucm_pass,
          new_pattern=profile.get("home_pattern", ""),
          profile_key=key,
        )
      except Exception:
        # Fail-safe worker should never crash the app thread pool.
        pass
      finally:
        with TWILIO_INBOUND_AUTO_RESTORE_LOCK:
          existing = TWILIO_INBOUND_AUTO_RESTORE_TIMERS.get(key)
          if existing and existing.get("timer") is timer_ref.get("timer"):
            TWILIO_INBOUND_AUTO_RESTORE_TIMERS.pop(key, None)

    timer = threading.Timer(TWILIO_INBOUND_AUTO_RESTORE_SECONDS, _run_auto_restore)
    timer.daemon = True
    timer_ref["timer"] = timer

    with TWILIO_INBOUND_AUTO_RESTORE_LOCK:
      existing = TWILIO_INBOUND_AUTO_RESTORE_TIMERS.pop(key, None)
      existing_timer = existing.get("timer") if isinstance(existing, dict) else None
      if existing_timer:
        existing_timer.cancel()

      TWILIO_INBOUND_AUTO_RESTORE_TIMERS[key] = {
        "timer": timer,
        "restore_at": restore_at_epoch,
      }

    timer.start()
    return restore_at_epoch


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

  def _find_dn(text: str) -> str:
    # Prefer full PSTN-looking numbers first, then any DN length >= 4.
    for pattern in (r"\b(\d{10,11})\b", r"\b(\d{4,})\b"):
      match = re.search(pattern, text or "")
      if match:
        return match.group(1)
    return ""

  fallback_dn = ""
  for row in reader:
    if len(row) < 3:
      continue

    step = (row[0] or "").strip()
    status = (row[1] or "").strip().lower()
    details = (row[2] or "").strip()
    if status != "success":
      continue

    # Primary row emitted by secondary-device workflows.
    if step == "Resolve DN":
      dn = _find_dn(details)
      if dn:
        return dn

    # Alternate success row emitted when a mobile device is actually created.
    # Example: "Created TCT945... with shared DN 9451234567"
    if step in {"Add TCT Device", "Add BOT Device"} or "shared DN" in details:
      dn = _find_dn(details)
      if dn and not fallback_dn:
        fallback_dn = dn

  return fallback_dn


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
      verify=False,
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


def _lookup_user_primary_extension(cucm_host: str, cucm_user: str, cucm_pass: str, target_user: str) -> str:
    clean_target = (target_user or "").strip()
    if not clean_target:
      return ""

    soap = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axl=\"http://www.cisco.com/AXL/API/15.0\">
  <soapenv:Header/>
  <soapenv:Body>
    <axl:getUser>
      <userid>{escape(clean_target)}</userid>
      <returnedTags>
        <primaryExtension>
          <pattern/>
        </primaryExtension>
      </returnedTags>
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
      verify=False,
    )
    if response.status_code != 200:
      return ""

    try:
      root = ET.fromstring(response.text)
    except Exception:
      return ""

    for elem in root.iter():
      if elem.tag.split("}")[-1] == "pattern":
        value = (elem.text or "").strip()
        if value:
          return value

    return ""

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
    if not (phone_number or "").strip():
      phone_number = _lookup_user_primary_extension(cucm_host, cucm_user, cucm_pass, target_user)

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
      number = _lookup_user_primary_extension(cucm_host, cucm_user, cucm_pass, target_user)
    if not number:
      return "Skipped", "No Jabber number was resolved for this user; email not sent"

    recipient, _display_name = _lookup_user_contact(cucm_host, cucm_user, cucm_pass, target_user)
    recipient = (recipient or "").strip()
    if not recipient:
      return "Failed", "Target user does not have a CUCM mailid; email not sent"

    phone_text = _format_notification_phone(number)
    subject = f"Cisco Jabber is ready for use - telephone number {phone_text} assigned"
    body = (
      "Welcome to AMN Healthcare\n\n"
      f"Cisco Jabber has been created, and ready for your use. The Telephone number assigned to you is {phone_text}.\n\n"
      "What is Cisco Jabber?  Jabber is what you will be using to make voice calls, providing secure and reliable communication.\n\n"
      "Please click on the link below for video training on how to use of Cisco Jabber.\n"
      f"Watch and Learn Cisco Jabber Softphone \n{CSF_JABBER_TRAINING_URL}"
    )
    html_body = (
      "<p>Welcome to AMN Healthcare</p>"
      f"<p>Cisco Jabber has been created, and ready for your use. The Telephone number assigned to you is {escape(phone_text)}.</p>"
      "<p>What is Cisco Jabber? Jabber is what you will be using to make voice calls, providing secure and reliable communication.</p>"
      "<p>Please click on the link below for video training on how to use of Cisco Jabber.<br>"
      f"<a href=\"{escape(CSF_JABBER_TRAINING_URL)}\">Watch and Learn Cisco Jabber Softphone 12.9.mp4</a></p>"
    )

    _send_smtp_email(
      sender=CSF_JABBER_EMAIL_FROM,
      recipients=[recipient],
      subject=subject,
      body=body,
      html_body=html_body,
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
def genesys_admin_placeholder(request: Request):
  session = _get_auth_session(request) or {}
  auth_cucm_host = str(session.get("cucm_host", "") or "").strip()
  auth_user = str(session.get("username", "") or "").strip()
  html = """
<html>
  <head>
    <title>Genesys Admin</title>
    <style>
      :root {
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-text: #12304a;
        --amn-text-soft: #4e6a84;
        --amn-border: #c8dbee;
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
        background: linear-gradient(120deg, rgba(0, 47, 108, 0.98), rgba(0, 94, 184, 0.94));
        color: #fff;
        box-shadow: 0 12px 28px rgba(0, 47, 108, 0.22);
      }

      .topbar-brand {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .topbar-btn {
        display: inline-block;
        padding: 7px 12px;
        border-radius: 10px;
        font-size: 12px;
        font-weight: 700;
        text-decoration: none;
        border: 1px solid rgba(255, 255, 255, 0.65);
        color: #fff;
      }

      .content {
        max-width: 1400px;
        margin: 8px auto 14px auto;
        padding: 0 12px 12px 12px;
      }

      .page-hero {
        padding: 12px 14px;
        margin-bottom: 10px;
        border-radius: 12px;
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.96), rgba(239, 247, 255, 0.95));
        border: 1px solid rgba(0, 47, 108, 0.1);
        box-shadow: var(--amn-shadow);
      }

      .page-title {
        margin: 0;
        color: var(--amn-navy);
        font-size: 22px;
      }

      .page-subtitle {
        margin: 6px 0 0 0;
        color: var(--amn-text-soft);
        font-size: 13px;
      }

      .portal-shell {
        display: grid;
        grid-template-columns: 244px minmax(0, 1fr);
        gap: 10px;
        align-items: start;
        margin-top: 8px;
      }

      .portal-sidebar {
        position: sticky;
        top: 54px;
        background: linear-gradient(180deg, rgba(0, 47, 108, 0.97), rgba(7, 75, 138, 0.96));
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 12px;
        padding: 8px;
        box-shadow: 0 18px 36px rgba(0, 47, 108, 0.18);
      }

      .portal-sidebar h4 {
        margin: 4px 6px 8px 6px;
        color: #fff;
        font-size: 13px;
      }

      .portal-nav-btn {
        width: 100%;
        text-align: left;
        background: linear-gradient(90deg, #ffffff, #ecf6ff);
        color: var(--amn-navy);
        border: 1px solid rgba(255, 255, 255, 0.92);
        border-radius: 8px;
        padding: 7px 8px;
        font-size: 12px;
        line-height: 1.25;
        font-weight: 700;
      }

      .panel {
        background: #fff;
        border: 1px solid var(--amn-border);
        border-radius: 12px;
        padding: 14px;
        box-shadow: var(--amn-shadow);
      }

      .search-filter-row {
        display: flex;
        gap: 8px;
        align-items: center;
        flex-wrap: wrap;
        margin-bottom: 8px;
      }

      input,
      select,
      button {
        border-radius: 10px;
        border: 1px solid var(--amn-border);
      }

      input,
      select {
        min-height: 34px;
        padding: 6px 8px;
      }

      button {
        background: linear-gradient(180deg, #0c77d8, #005eb8);
        color: #fff;
        border: none;
        padding: 8px 12px;
        font-weight: 700;
        cursor: pointer;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
      }

      th,
      td {
        padding: 7px 10px;
        border-bottom: 1px solid #c8dbee;
        text-align: left;
      }

      thead tr {
        background: #005eb8;
        color: #fff;
      }
    </style>
  </head>
  <body>
    <header class="topbar">
      <div class="topbar-brand">
        <strong>Voice Operations Portal</strong>
      </div>
      <div>
        <a class="topbar-btn" href="/">Back to Login</a>
      </div>
    </header>

    <main class="content">
      <section class="page-hero">
        <h2 class="page-title">Genesys Admin</h2>
        <p class="page-subtitle">Starter workflow: extract Genesys Cloud users by last name and optional first name.</p>
      </section>

      <div class="portal-shell">
        <aside class="portal-sidebar">
          <h4>Genesys Menu</h4>
          <button type="button" class="portal-nav-btn">Extract User by Name</button>
          <button type="button" class="portal-nav-btn">Queue Lookup</button>
        </aside>

        <section class="portal-main">
          <div class="panel">
            <h3 style="margin-top:0;">Extract User by Name</h3>

            <form id="genesys-user-search-form">
              <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <div class="search-filter-row">
                <input name="last_name" placeholder="Last Name *" style="width:220px;" required>
                <input name="first_name" placeholder="First Name (optional)" style="width:220px;">
                <button type="submit">Extract User Data</button>
              </div>
            </form>

            <p id="genesys-user-search-status" style="color:#2c5c8a; min-height:18px;">Ready.</p>
            <div id="genesys-user-raw-download" style="margin:6px 0 10px 0;"></div>
            <div id="genesys-user-search-results" style="overflow-x:auto;"></div>
          </div>

          <div class="panel" style="margin-top:12px;">
            <h3 style="margin-top:0;">Queue Lookup</h3>
            <form id="genesys-queue-search-form">
              <div class="search-filter-row">
                <input name="queue_name" placeholder="Queue Name or Queue ID *" style="width:340px;" required>
                <button type="submit">Lookup Queue Members</button>
              </div>
            </form>
            <p id="genesys-queue-search-status" style="color:#2c5c8a; min-height:18px;">Ready.</p>
            <div id="genesys-queue-search-results" style="overflow-x:auto;"></div>
          </div>
        </section>
      </div>
    </main>

    <script>
      (function () {
        const form = document.getElementById("genesys-user-search-form");
        const statusEl = document.getElementById("genesys-user-search-status");
        const rawDownloadEl = document.getElementById("genesys-user-raw-download");
        const resultsEl = document.getElementById("genesys-user-search-results");
        const queueForm = document.getElementById("genesys-queue-search-form");
        const queueStatusEl = document.getElementById("genesys-queue-search-status");
        const queueResultsEl = document.getElementById("genesys-queue-search-results");
        if (form && statusEl && resultsEl && rawDownloadEl) {
          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Running Genesys lookup...";
            rawDownloadEl.innerHTML = "";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              const response = await fetch("/genesys/users/extract", {
                method: "POST",
                body: formData,
              });
              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.error) || "Genesys lookup failed.");
              }

              const rows = payload.rows || [];
              const emailTargetCount = Number(payload.cucm_email_targets || 0);
              const warningCount = Array.isArray(payload.warnings) ? payload.warnings.length : 0;
              statusEl.textContent = "Region: " + (payload.region || "") + " | CUCM Emails: " + emailTargetCount + " | Matches: " + rows.length + " | Warnings: " + warningCount;
              if (payload.raw_download_url) {
                const rawName = payload.raw_filename || "genesys_user_extract.json";
                rawDownloadEl.innerHTML = "<a href='" + payload.raw_download_url + "' style='display:inline-block;padding:7px 10px;background:#385977;color:#fff;border-radius:6px;text-decoration:none;font-weight:700;'>Download Raw Genesys JSON (" + rawName + ")</a>";
              }

              if (!rows.length) {
                resultsEl.innerHTML = "<p style='color:#4e6a84;'>No matching users found.</p>";
                return;
              }

              let html = "<table><thead><tr>";
              html += "<th>Name</th><th>Email</th><th>Username</th><th>Division</th><th>WebRTC Phone</th><th>Action</th><th>Template Source</th><th>Template Phone</th><th>Template Site ID</th><th>Template Base Settings</th><th>Template Lines</th><th>ACD Skills</th><th>Queues</th><th>State</th><th>User ID</th>";
              html += "</tr></thead><tbody>";
              rows.forEach(function (row, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                html += "<tr style='background:" + bg + ";'>";
                html += "<td>" + (row.name || "") + "</td>";
                html += "<td>" + (row.email || "") + "</td>";
                html += "<td>" + (row.username || "") + "</td>";
                html += "<td>" + (row.division || "") + "</td>";
                html += "<td>" + (row.webrtc_phone || "") + "</td>";
                if (row.can_build_webrtc) {
                  html += "<td><button type='button' class='genesys-build-btn' data-user-id='" + (row.id || "") + "' data-user-name='" + (row.name || "") + "'>Build + Associate</button></td>";
                } else {
                  html += "<td><span style='color:#2d7a43;font-weight:700;'>Already Present</span></td>";
                }
                html += "<td>" + (row.phone_template_source || "") + "</td>";
                html += "<td>" + (row.phone_template_name || "") + "</td>";
                html += "<td style='font-family:Consolas,monospace;'>" + (row.phone_template_site_id || "") + "</td>";
                html += "<td style='font-family:Consolas,monospace;'>" + (row.phone_template_base_settings_id || "") + "</td>";
                html += "<td>" + (row.phone_template_line_count || 0) + "</td>";
                html += "<td>" + (row.acd_skills || "") + "</td>";
                html += "<td>" + (row.queues || "") + "</td>";
                html += "<td>" + (row.state || "") + "</td>";
                html += "<td style='font-family:Consolas,monospace;'>" + (row.id || "") + "</td>";
                html += "</tr>";
              });
              html += "</tbody></table>";
              resultsEl.innerHTML = html;

              const buildButtons = resultsEl.querySelectorAll(".genesys-build-btn");
              buildButtons.forEach(function (btn) {
                btn.addEventListener("click", async function () {
                  const userId = String(btn.getAttribute("data-user-id") || "").trim();
                  const userName = String(btn.getAttribute("data-user-name") || "").trim();
                  if (!userId) return;

                  btn.disabled = true;
                  const originalText = btn.textContent;
                  btn.textContent = "Building...";
                  statusEl.textContent = "Building WebRTC phone for " + userName + "...";

                  try {
                    const buildForm = new FormData();
                    buildForm.append("user_id", userId);
                    buildForm.append("user_name", userName);

                    const buildResponse = await fetch("/genesys/users/build-webrtc", {
                      method: "POST",
                      body: buildForm,
                    });
                    const buildPayload = await buildResponse.json();
                    if (!buildResponse.ok || !buildPayload.ok) {
                      throw new Error((buildPayload && buildPayload.error) || "Build failed.");
                    }

                    btn.textContent = "Built";
                    btn.style.background = "#2d7a43";
                    btn.style.color = "#fff";
                    statusEl.textContent = "Build success for " + userName + ": " + (buildPayload.phone_name || "") + " (" + (buildPayload.association_result || "") + ")";
                  } catch (buildErr) {
                    btn.disabled = false;
                    btn.textContent = originalText;
                    statusEl.textContent = "Build failed for " + userName + ": " + ((buildErr && buildErr.message) || "Unknown error.");
                  }
                });
              });
            } catch (err) {
              statusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        }

        if (queueForm && queueStatusEl && queueResultsEl) {
          queueForm.addEventListener("submit", async function (event) {
            event.preventDefault();
            queueStatusEl.textContent = "Running queue lookup...";
            queueResultsEl.innerHTML = "";

            try {
              const formData = new FormData(queueForm);
              const response = await fetch("/genesys/queues/lookup", {
                method: "POST",
                body: formData,
              });
              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.error) || "Queue lookup failed.");
              }

              const rows = payload.rows || [];
              const warnings = Array.isArray(payload.warnings) ? payload.warnings.length : 0;
              const diagnostics = Array.isArray(payload.diagnostics) ? payload.diagnostics : [];
              const directQueueId = String(payload.direct_queue_id || "");
              queueStatusEl.textContent = "Queue Query: " + (payload.query || "") + " | Direct Queue ID: " + (directQueueId || "(none)") + " | Matched Queues: " + ((payload.queues || []).length || 0) + " | Member Rows: " + rows.length + " | Warnings: " + warnings + " | Diagnostics: " + diagnostics.length;

              if (!rows.length) {
                let noRowsHtml = "<p style='color:#4e6a84;'>No queue members found for this query.</p>";
                if (diagnostics.length) {
                  noRowsHtml += "<div style='margin-top:8px;padding:8px;border:1px solid #d7e3ee;border-radius:6px;background:#f9fcff;'><strong>Diagnostics</strong><pre style='white-space:pre-wrap;margin:6px 0 0 0;font-size:12px;line-height:1.35;'>" + diagnostics.join("\n") + "</pre></div>";
                }
                queueResultsEl.innerHTML = noRowsHtml;
                return;
              }

              let html = "<table><thead><tr>";
              html += "<th>Queue Name</th><th>Queue ID</th><th>Member Name</th><th>Member Email</th><th>Member Username</th><th>Member ID</th>";
              html += "</tr></thead><tbody>";
              rows.forEach(function (row, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                html += "<tr style='background:" + bg + ";'>";
                html += "<td>" + (row.queue_name || "") + "</td>";
                html += "<td style='font-family:Consolas,monospace;'>" + (row.queue_id || "") + "</td>";
                html += "<td>" + (row.member_name || "") + "</td>";
                html += "<td>" + (row.member_email || "") + "</td>";
                html += "<td>" + (row.member_username || "") + "</td>";
                html += "<td style='font-family:Consolas,monospace;'>" + (row.member_id || "") + "</td>";
                html += "</tr>";
              });
              html += "</tbody></table>";
              if (diagnostics.length) {
                html += "<div style='margin-top:8px;padding:8px;border:1px solid #d7e3ee;border-radius:6px;background:#f9fcff;'><strong>Diagnostics</strong><pre style='white-space:pre-wrap;margin:6px 0 0 0;font-size:12px;line-height:1.35;'>" + diagnostics.join("\n") + "</pre></div>";
              }
              queueResultsEl.innerHTML = html;
            } catch (err) {
              queueStatusEl.textContent = "Queue lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        }
      })();
    </script>
  </body>
</html>
"""
  html = html.replace("__AUTH_CUCM_HOST__", escape(auth_cucm_host))
  html = html.replace("__AUTH_USER__", escape(auth_user))
  return HTMLResponse(html)


@app.post("/genesys/users/extract")
def genesys_extract_users_route(
  request: Request,
  region: str = Form(""),
  last_name: str = Form(""),
  first_name: str = Form(""),
  cucm_host: str = Form(""),
  cucm_user: str = Form(""),
  cucm_pass: str = Form(""),
):
  session = _get_auth_session(request) or {}
  clean_region = (GENESYS_CLOUD_REGION or "usw2").strip().lower() or "usw2"
  clean_client_id = GENESYS_CLIENT_ID
  clean_client_secret = GENESYS_CLIENT_SECRET
  clean_last = (last_name or "").strip()
  clean_first = (first_name or "").strip()
  clean_cucm_host = (cucm_host or "").strip() or str(session.get("cucm_host", "") or "").strip()
  clean_cucm_user = (cucm_user or "").strip() or str(session.get("username", "") or "").strip()
  clean_cucm_pass = (cucm_pass or "").strip() or _get_cached_secret(session, "cucm_pass")

  if not clean_last:
    return JSONResponse({"ok": False, "error": "Last name is required.", "rows": []}, status_code=400)

  token_result = _genesys_get_access_token(clean_region, clean_client_id, clean_client_secret)
  if not token_result.get("ok"):
    return JSONResponse({
      "ok": False,
      "error": token_result.get("error", "Genesys token request failed."),
      "rows": [],
    }, status_code=400)

  cucm_email_targets = set()
  if clean_cucm_host and clean_cucm_user and clean_cucm_pass:
    try:
      cucm_people = search_persons_by_name(
        clean_cucm_host,
        clean_cucm_user,
        clean_cucm_pass,
        clean_last,
        clean_first,
      )
      for person in cucm_people or []:
        email_value = str(person.get("email", "") or "").strip().lower()
        if email_value:
          cucm_email_targets.add(email_value)
    except Exception:
      # Non-blocking: Genesys direct lookup still runs.
      pass

  search_result = _genesys_search_users_by_name(
    token_result.get("region", clean_region),
    token_result.get("access_token", ""),
    clean_last,
    clean_first,
    cucm_email_targets,
  )
  if not search_result.get("ok"):
    return JSONResponse({
      "ok": False,
      "error": search_result.get("error", "Genesys user lookup failed."),
      "rows": [],
    }, status_code=400)

  enrich_result = _genesys_enrich_user_rows(
    token_result.get("region", clean_region),
    token_result.get("access_token", ""),
    search_result.get("rows", []),
  )

  raw_payload = {
    "generated_at": _audit_now().strftime(AUDIT_TIMESTAMP_FORMAT),
    "region": enrich_result.get("region", search_result.get("region", clean_region)),
    "lookup": {
      "last_name": clean_last,
      "first_name": clean_first,
      "cucm_email_targets": sorted(cucm_email_targets),
    },
    "warnings": enrich_result.get("warnings", []),
    "items": enrich_result.get("raw_items", []),
  }
  raw_filename = f"genesys_user_extract_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
  raw_job_id = _store_job_output(
    json.dumps(raw_payload, indent=2).encode("utf-8"),
    raw_filename,
    "application/json",
  )

  return JSONResponse({
    "ok": True,
    "region": enrich_result.get("region", search_result.get("region", clean_region)),
    "rows": enrich_result.get("rows", search_result.get("rows", [])),
    "cucm_email_targets": len(cucm_email_targets),
    "warnings": enrich_result.get("warnings", []),
    "raw_download_url": f"/download/job-output/{raw_job_id}",
    "raw_filename": raw_filename,
  })


@app.post("/genesys/queues/lookup")
def genesys_queue_lookup_route(queue_name: str = Form("")):
  clean_queue_name = (queue_name or "").strip()
  clean_region = (GENESYS_CLOUD_REGION or "usw2").strip().lower() or "usw2"
  if not clean_queue_name:
    return JSONResponse({"ok": False, "error": "Queue name is required."}, status_code=400)

  token_result = _genesys_get_access_token(clean_region, GENESYS_CLIENT_ID, GENESYS_CLIENT_SECRET)
  if not token_result.get("ok"):
    return JSONResponse({
      "ok": False,
      "error": token_result.get("error", "Genesys token request failed."),
    }, status_code=400)

  region = token_result.get("region", clean_region)
  _, _, api_base = _genesys_region_to_urls(region)
  access_token = token_result.get("access_token", "")

  queue_items = []
  direct_queue_id = _genesys_extract_queue_id_hint(clean_queue_name)
  if direct_queue_id:
    queue_items = [{
      "id": direct_queue_id,
      "name": _genesys_get_queue_name(api_base, access_token, direct_queue_id),
    }]
  else:
    search_items, queue_err = _genesys_search_queues_by_name(api_base, access_token, clean_queue_name)
    if queue_err:
      return JSONResponse({"ok": False, "error": queue_err}, status_code=400)
    queue_items = search_items

  warnings = []
  diagnostics = []
  rows = []
  queue_summaries = []
  for queue_item in queue_items[:15]:
    queue_id = str(queue_item.get("id", "") or "").strip()
    queue_label = str(queue_item.get("name", "") or "").strip() or queue_id
    members, member_diag, member_err = _genesys_get_queue_members_with_diagnostics(api_base, access_token, queue_id)
    for diag in member_diag:
      diagnostics.append(f"{queue_label} [{queue_id}] {diag}")
    if member_err:
      warnings.append(f"{queue_label}: {member_err}")
      continue

    queue_summaries.append({
      "queue_id": queue_id,
      "queue_name": queue_label,
      "member_count": len(members),
    })

    if not members:
      rows.append({
        "queue_name": queue_label,
        "queue_id": queue_id,
        "member_name": "(none)",
        "member_email": "",
        "member_username": "",
        "member_id": "",
      })
      continue

    for member in members:
      user_obj = member.get("user") if isinstance(member.get("user"), dict) else {}
      member_name = str(user_obj.get("name", "") or member.get("name", "") or "").strip()
      member_email = str(user_obj.get("email", "") or member.get("email", "") or "").strip()
      member_username = str(user_obj.get("username", "") or member.get("username", "") or "").strip()
      member_id = str(user_obj.get("id", "") or member.get("id", "") or member.get("memberId", "") or "").strip()
      rows.append({
        "queue_name": queue_label,
        "queue_id": queue_id,
        "member_name": member_name,
        "member_email": member_email,
        "member_username": member_username,
        "member_id": member_id,
      })

  return JSONResponse({
    "ok": True,
    "region": region,
    "query": clean_queue_name,
    "direct_queue_id": direct_queue_id,
    "queues": queue_summaries,
    "rows": rows,
    "warnings": warnings,
    "diagnostics": diagnostics,
  })


@app.post("/genesys/users/build-webrtc")
def genesys_build_webrtc_route(
  user_id: str = Form(""),
  user_name: str = Form(""),
):
  clean_user_id = (user_id or "").strip()
  clean_user_name = (user_name or "").strip()
  clean_region = (GENESYS_CLOUD_REGION or "usw2").strip().lower() or "usw2"

  if not clean_user_id:
    return JSONResponse({"ok": False, "error": "user_id is required."}, status_code=400)

  token_result = _genesys_get_access_token(clean_region, GENESYS_CLIENT_ID, GENESYS_CLIENT_SECRET)
  if not token_result.get("ok"):
    return JSONResponse({
      "ok": False,
      "error": token_result.get("error", "Genesys token request failed."),
    }, status_code=400)

  build_result = _genesys_build_webrtc_phone_for_user(
    token_result.get("region", clean_region),
    token_result.get("access_token", ""),
    clean_user_id,
    clean_user_name,
  )
  if not build_result.get("ok"):
    return JSONResponse({
      "ok": False,
      "error": build_result.get("error", "WebRTC phone build failed."),
    }, status_code=400)

  return JSONResponse({
    "ok": True,
    "region": build_result.get("region", clean_region),
    "phone_id": build_result.get("phone_id", ""),
    "phone_name": build_result.get("phone_name", ""),
    "create_mode": build_result.get("create_mode", ""),
    "association_result": build_result.get("association_result", ""),
  })


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

  session_id = _create_auth_session(cucm_host, cucm_user, cucm_pass)
  response = RedirectResponse(url="/menu", status_code=303)
  response.set_cookie(
    key=SESSION_COOKIE_NAME,
    value=session_id,
    httponly=True,
    samesite="lax",
    secure=True,
    max_age=CREDENTIAL_CACHE_TTL_SECONDS,
  )
  return response


@app.get("/logout")
def logout(request: Request):
  session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
  if session_id:
    AUTH_SESSIONS.pop(session_id, None)
    AUTH_SESSION_SECRETS.pop(session_id, None)

  response = RedirectResponse(url="/", status_code=303)
  response.delete_cookie(SESSION_COOKIE_NAME)
  return response


@app.get("/menu", response_class=HTMLResponse)
def menu_page(request: Request):
  session = _get_auth_session(request) or {}
  now_epoch = time.time()
  session_id = request.cookies.get(SESSION_COOKIE_NAME, "")
  session_username = str(session.get("username", ""))
  auth_user = escape(session_username)
  auth_cucm_host = str(session.get("cucm_host", ""))
  has_cached_cucm_pass = _has_valid_cached_secret(session, "cucm_pass", now_epoch)
  if not has_cached_cucm_pass and session_id:
    has_cached_cucm_pass = bool((AUTH_SESSION_SECRETS.get(session_id, {}).get("cucm_pass", "") or "").strip())
  has_cached_unity_pass = _has_valid_cached_secret(session, "unity_pass", now_epoch) or has_cached_cucm_pass
  credential_expires_at = float(session.get("credential_expires_at", 0) or 0)
  credential_expires_at_ms = int(credential_expires_at * 1000) if (has_cached_cucm_pass and credential_expires_at > 0) else 0
  env_text, env_css_class = _get_environment_label(auth_cucm_host)
  admin_card_html = "" if not _is_admin_user(session_username) else """
        <a class=\"hero-link-card\" href=\"/page2\">
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

      .topbar-status {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: center;
      }

      .topbar-status > * {
        display: inline-flex;
        align-items: center;
        min-height: 32px;
        padding: 6px 10px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.35);
        box-sizing: border-box;
        font-size: 11px;
        font-weight: 700;
        line-height: 1.1;
      }

      .topbar-auth-pill {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
      }

      .topbar-status .env-banner {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
        box-shadow: none;
      }

      .topbar-status .session-timer {
        background: linear-gradient(180deg, #fff4df, #ffdca3);
        color: #6a3c00;
        border-color: #f0b44a;
        box-shadow: 0 6px 12px rgba(198, 138, 18, 0.22);
      }

      .topbar-status .env-banner.env-banner-prod,
      .topbar-status .env-banner.env-banner-lab {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
        border-color: rgba(255, 255, 255, 0.35);
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

      .hero-status-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 4px;
      }

      .hero-status-row .env-banner {
        margin: 0;
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

      .session-timer {
        display: none;
        align-items: center;
        gap: 8px;
        padding: 9px 12px;
        margin: 0;
        border-radius: 12px;
        border: 1px solid #f0b44a;
        background: linear-gradient(180deg, #fff4df, #ffe4b8);
        color: #6a3c00;
        box-shadow: 0 10px 18px rgba(198, 138, 18, 0.2);
      }

      .session-timer .timer-label {
        font-weight: 700;
      }

      .session-timer .timer-value {
        font-family: Consolas, monospace;
        font-weight: 700;
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
        grid-template-columns: 244px minmax(0, 1fr);
        gap: 10px;
        align-items: start;
        margin-top: 8px;
      }

      .portal-sidebar {
        position: sticky;
        top: 54px;
        background: linear-gradient(180deg, rgba(0, 47, 108, 0.97), rgba(7, 75, 138, 0.96));
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 12px;
        padding: 8px;
        box-shadow: 0 18px 36px rgba(0, 47, 108, 0.18);
      }

      .portal-sidebar h4 {
        margin: 4px 6px 8px 6px;
        color: #fff;
        font-size: 13px;
        letter-spacing: 0.3px;
      }

      .portal-nav {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .portal-nav-btn {
        width: 100%;
        text-align: left;
        background: rgba(255, 255, 255, 0.09);
        color: rgba(255, 255, 255, 0.94);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 8px;
        padding: 7px 8px;
        font-size: 12px;
        line-height: 1.25;
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

      .portal-nav-btn.start-here-btn {
        background: linear-gradient(180deg, #fff7d8, #ffe8a3);
        border-color: #d7ac2a;
        color: #4f3900;
        box-shadow: 0 10px 18px rgba(198, 138, 18, 0.28);
        line-height: 1.3;
      }

      .portal-nav-btn.start-here-btn:hover,
      .portal-nav-btn.start-here-btn.active {
        background: linear-gradient(180deg, #ffefbb, #ffd978);
        border-color: #bd8e13;
        color: #3f2a00;
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
        width: min(220px, 100%);
      }

      .compact-inline-row {
        display: flex;
        align-items: center;
        gap: 6px;
        flex-wrap: wrap;
      }

      .compact-inline-row span {
        display: inline-block;
        width: 170px;
        font-weight: 600;
      }

      .compact-inline-row input {
        width: min(220px, 100%);
      }

      .search-filter-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-bottom: 14px;
      }

      .search-filter-row input {
        flex: 0 0 auto;
        width: 180px;
        padding: 8px 10px;
        border: 1px solid rgba(0, 47, 108, 0.2);
        border-radius: 6px;
        font-size: 14px;
      }

      .search-filter-row button {
        flex: 0 0 auto;
        padding: 8px 20px;
        background: linear-gradient(135deg, #0f5db8 0%, #0a3f7d 100%);
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-weight: 600;
        font-size: 14px;
      }

      .search-filter-row button:hover {
        background: linear-gradient(135deg, #0a3f7d 0%, #072f5f 100%);
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
        min-height: 340px;
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
      <div class="topbar-status">
        <span class="topbar-auth-pill">Authenticated Operator: __AUTH_USER__</span>
        <div class="env-banner __ENV_CLASS__">__ENV_TEXT__</div>
        <div id="session-timer-banner" class="session-timer" aria-live="polite">
          <span class="timer-label">Auto logout in:</span>
          <span id="session-timer-remaining" class="timer-value"></span>
        </div>
      </div>
      <div class="topbar-actions">
        <a class="topbar-btn topbar-btn-login" href="/">Log In</a>
        <a class="topbar-btn topbar-btn-logout" href="/logout">Log Out</a>
      </div>
    </header>

    <main class="content">
    <section class="page-hero">
      <div class="page-title-row">
        <div class="page-title-block">
          <h2 class="page-title">Cisco Voice Server Automation</h2>
          <p class="page-subtitle">CUCM and Unity operations with fast navigation and inline outputs.</p>
        </div>
        <div class="page-meta-card">
          <span class="page-meta-label">Portal Version</span>
          <span class="page-meta-value">v1.0 Current</span>
          <p class="page-meta-note">v1.01 queued for VeraSMART automation enhancement.</p>
        </div>
      </div>
      <div class="hero-link-grid">
        <a class="hero-link-card" href="/">
          <strong>Landing Page</strong>
          <span>Return to login and environment selection.</span>
        </a>
__ADMIN_CARD__
        <a class="hero-link-card" href="/audit-trail">
          <strong>Action History</strong>
          <span>Review recent portal actions and download the audit CSV.</span>
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
          <button type="button" class="portal-nav-btn start-here-btn active" data-panel="personlookup">Start Here!<br>Employee Lookup By Name</button>
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
      <form id="person-lookup-form" class="jabber-check-form">
        <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
        <input type="hidden" name="cucm_user" value="__AUTH_USER__">
        <input type="hidden" name="cucm_pass" value="">
        <input type="hidden" name="include_teams_status" value="1">

        <div class="search-filter-row">
          <input name="last_name" placeholder="Last Name *" required>
          <input name="first_name" placeholder="First Name (optional)">
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
        window.__hasCachedCucmPassword = __HAS_CACHED_CUCM_PASS__;
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
              const normalized = String(msg || "").toLowerCase();
              if (
                response.status === 401
                || normalized.includes("credentials expired")
                || normalized.includes("log in again")
                || normalized.includes("missing cucm credentials")
              ) {
                throw new Error("Session credentials expired. Please log in again.");
              }
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
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Teams Telephony</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Jabber Devices</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Actions</th>';
            html += '</tr></thead><tbody>';

            results.forEach(function (r, i) {
              const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
              const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
              const ext = r.primary_extension || "\u2014";
              const email = r.email || "\u2014";
              const telephone = r.telephone || "\u2014";
              const uid = r.userid || "";
              const teams = r.teams_telephony || {};
              const teamsIsUser = !!teams.is_teams_user;
              const teamsState = teams.status || (teamsIsUser ? "Yes" : "Not Found");
              const teamsExt = teams.extension || "";
              const teamsText = teamsIsUser
                ? (teamsExt ? `Yes (${teamsExt})` : "Yes")
                : (teamsState === "Unknown" ? "Unknown" : "Not Found");
              const teamsColor = teamsIsUser ? "#0f6d35" : (teamsState === "Unknown" ? "#7a1020" : "#6b7280");
              const devList = (r.devices || []).map(function (d) {
                const exts = (d.extensions || []).join(", ") || "\u2014";
                return "<strong>" + d.name + "</strong> <span style='color:#555;font-size:12px;'>[" + d.type + "] " + exts + "</span>";
              }).join("<br>") || "\u2014";

              const btnStyle = "display:inline-block;margin:0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;";
              const actionBtns =
                `<button type="button" style="${btnStyle}background:#005eb8;color:#fff;" onclick="prefillPanel('precheck','${uid}')">Check Jabber</button>` +
                `<button type="button" style="${btnStyle}background:#237741;color:#fff;" onclick="prefillPanel('build','${uid}')">Build Jabber</button>` +
                `<button type="button" style="${btnStyle}background:#0e7490;color:#fff;" onclick="prefillPanel('tct','${uid}')">Build iPhone</button>` +
                `<button type="button" style="${btnStyle}background:#7c3aed;color:#fff;" onclick="prefillPanel('bot','${uid}')">Build Android</button>` +
                `<button type="button" style="${btnStyle}background:#0f766e;color:#fff;" data-mobile-resend-uid="${uid}">Re-send Mobile Email</button>` +
                `<button type="button" style="${btnStyle}background:#1f7a3d;color:#fff;" data-lookup-notify-uid="${uid}" data-lookup-notify-tel="${(r.telephone || "")}">Send New Jabber Email</button>` +
                `<button type="button" style="${btnStyle}background:#b45309;color:#fff;" onclick="prefillPanel('pin','${uid}')">Reset Voicemail PIN</button>` +
                `<button type="button" style="${btnStyle}background:#8a5a00;color:#fff;" onclick="prefillPanel('namechange','${uid}')">Name Update</button>`;

              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
              html += '<td style="padding:7px 10px;">' + name + '</td>';
              html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
              html += '<td style="padding:7px 10px; font-weight:700; color:#002f6c;">' + ext + '</td>';
              html += '<td style="padding:7px 10px;">' + email + '</td>';
              html += '<td style="padding:7px 10px;">' + telephone + '</td>';
              html += '<td style="padding:7px 10px; font-weight:700; color:' + teamsColor + ';">' + teamsText + '</td>';
              html += '<td style="padding:7px 10px; line-height:1.6;">' + devList + '</td>';
              html += '<td style="padding:7px 10px;"><div style="display:grid;grid-template-columns:repeat(4,max-content);gap:4px;align-items:start;">' + actionBtns + '</div></td>';
              html += '</tr>';
            });

            html += '</tbody></table>';
            resultsEl.innerHTML = html;

            resultsEl.querySelectorAll('button[data-lookup-notify-uid]').forEach(function (btn) {
              btn.addEventListener("click", async function () {
                const uid = btn.getAttribute("data-lookup-notify-uid") || "";
                const tel = btn.getAttribute("data-lookup-notify-tel") || "";
                const cucmHost = "__AUTH_CUCM_HOST__";
                const cucmUser = "__AUTH_USER__";
                const cucmPass = "";
                const origText = btn.textContent;

                btn.disabled = true;
                btn.textContent = "Sending...";
                statusEl.textContent = `Sending Jabber notification for ${uid}...`;
                try {
                  const sf = new FormData();
                  sf.append("cucm_host", cucmHost);
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
                  const raw = await sr.text();
                  let sp = null;
                  try {
                    sp = raw ? JSON.parse(raw) : {};
                  } catch (_parseErr) {
                    sp = { ok: false, detail: `Unexpected response from server (HTTP ${sr.status}).` };
                  }
                  if (!sr.ok || !sp.ok) {
                    throw new Error((sp && sp.detail) || "Send failed.");
                  }
                  btn.textContent = "\u2713 Sent";
                  btn.style.background = "#166534";
                  statusEl.textContent = "Notification sent: " + (sp.detail || "Email sent successfully.");
                } catch (err) {
                  btn.textContent = origText;
                  btn.disabled = false;
                  statusEl.textContent = "Send failed: " + ((err && err.message) || "Unknown error.");
                }
              });
            });

            resultsEl.querySelectorAll('button[data-mobile-resend-uid]').forEach(function (btn) {
              btn.addEventListener("click", async function () {
                const uid = btn.getAttribute("data-mobile-resend-uid") || "";
                const cucmHost = "__AUTH_CUCM_HOST__";
                const cucmUser = "__AUTH_USER__";
                const cucmPass = "";
                const origText = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Sending...";
                statusEl.textContent = `Sending mobile Jabber email for ${uid}...`;
                try {
                  const sf = new FormData();
                  sf.append("cucm_host", cucmHost);
                  sf.append("cucm_user", cucmUser);
                  sf.append("cucm_pass", cucmPass);
                  sf.append("target_user", uid);
                  const sr = await fetch("/send/mobile-jabber-email", {
                    method: "POST",
                    body: sf,
                    credentials: "same-origin",
                    headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                  });
                  const raw = await sr.text();
                  let sp = null;
                  try { sp = raw ? JSON.parse(raw) : {}; } catch (_) { sp = { ok: false, detail: `Unexpected response (HTTP ${sr.status}).` }; }
                  if (!sr.ok || !sp.ok) throw new Error((sp && sp.detail) || "Send failed.");
                  btn.textContent = "\u2713 Sent";
                  btn.style.background = "#166534";
                  statusEl.textContent = "Mobile email sent for " + uid + ": " + (sp.detail || "Success.");
                } catch (err) {
                  btn.textContent = origText;
                  btn.disabled = false;
                  statusEl.textContent = "Mobile email failed: " + ((err && err.message) || "Unknown error.");
                }
              });
            });

          } catch (err) {
            const normalized = String((err && err.message) || "").toLowerCase();
            if (
              normalized.includes("credentials expired")
              || normalized.includes("log in again")
              || normalized.includes("missing cucm credentials")
            ) {
              statusEl.textContent = "Session expired. Please log in again from the landing page.";
              return;
            }
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

              const btnStyle = "display:inline-block;margin:0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;";
              const actionBtns = uid
                ? `<button type="button" style="${btnStyle}background:#005eb8;color:#fff;" onclick="prefillPanel('precheck','${uid}')">Check Jabber</button>` +
                  `<button type="button" style="${btnStyle}background:#237741;color:#fff;" onclick="prefillPanel('build','${uid}')">Build Jabber</button>` +
                  `<button type="button" style="${btnStyle}background:#0f766e;color:#fff;" data-mobile-resend-uid="${uid}">Re-send Mobile Email</button>`
                : "\u2014";

              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
              html += '<td style="padding:7px 10px; font-weight:700; color:#002f6c; font-family:Consolas,monospace;">' + m.pattern + '</td>';
              html += '<td style="padding:7px 10px; font-size:12px;">' + (m.partition || "\u2014") + '</td>';
              html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + dev + '</td>';
              html += '<td style="padding:7px 10px; font-size:12px;">' + devType + '</td>';
              html += '<td style="padding:7px 10px;">' + ownerCell + '</td>';
              html += '<td style="padding:7px 10px; font-size:12px; color:#355978;">' + allLines + '</td>';
              html += '<td style="padding:7px 10px;"><div style="display:grid;grid-template-columns:repeat(2,max-content);gap:4px;align-items:start;">' + actionBtns + '</div></td>';
              html += '</tr>';
            });

            html += '</tbody></table>';
            resultsEl.innerHTML = html;

            resultsEl.querySelectorAll('button[data-mobile-resend-uid]').forEach(function (btn) {
              btn.addEventListener("click", async function () {
                const uid = btn.getAttribute("data-mobile-resend-uid") || "";
                const cucmHost = "__AUTH_CUCM_HOST__";
                const cucmUser = "__AUTH_USER__";
                const cucmPass = "";
                const origText = btn.textContent;
                btn.disabled = true;
                btn.textContent = "Sending...";
                statusEl.textContent = `Sending mobile Jabber email for ${uid}...`;
                try {
                  const sf = new FormData();
                  sf.append("cucm_host", cucmHost);
                  sf.append("cucm_user", cucmUser);
                  sf.append("cucm_pass", cucmPass);
                  sf.append("target_user", uid);
                  const sr = await fetch("/send/mobile-jabber-email", {
                    method: "POST",
                    body: sf,
                    credentials: "same-origin",
                    headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                  });
                  const raw = await sr.text();
                  let sp = null;
                  try { sp = raw ? JSON.parse(raw) : {}; } catch (_) { sp = { ok: false, detail: `Unexpected response (HTTP ${sr.status}).` }; }
                  if (!sr.ok || !sp.ok) throw new Error((sp && sp.detail) || "Send failed.");
                  btn.textContent = "\u2713 Sent";
                  btn.style.background = "#166534";
                  statusEl.textContent = "Mobile email sent for " + uid + ": " + (sp.detail || "Success.");
                } catch (err) {
                  btn.textContent = origText;
                  btn.disabled = false;
                  statusEl.textContent = "Mobile email failed: " + ((err && err.message) || "Unknown error.");
                }
              });
            });

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
          <option value="recruiter">Recruiter</option>
          <option value="general" selected>General FTE</option>
          <option value="strike">Strike</option>
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
          <div class="compact-inline-row">
            <span>Last Name:</span>
            <input id="teams-lookup-last-name" placeholder="Smith" required>
          </div><br>

          <div class="compact-inline-row">
            <span>First Name (optional):</span>
            <input id="teams-lookup-first-name" placeholder="John">
          </div><br>

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

            if (!cucmUser || (!cucmPass && window.__hasCachedCucmPassword !== true)) {
              lookupStatusEl.textContent = "Enter CUCM username and password (or use cached login) before searching.";
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
                const normalized = String(msg || "").toLowerCase();
                if (
                  response.status === 401
                  || normalized.includes("credentials expired")
                  || normalized.includes("log in again")
                  || normalized.includes("missing cucm credentials")
                ) {
                  window.location.href = "/logout";
                  return;
                }
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
          <div class="compact-inline-row">
            <span>Last Name:</span>
            <input id="teams-remove-last-name" placeholder="Smith" required>
          </div><br>

          <div class="compact-inline-row">
            <span>First Name (optional):</span>
            <input id="teams-remove-first-name" placeholder="John">
          </div><br>

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

        if (!cucmUser || (!cucmPass && window.__hasCachedCucmPassword !== true)) {
          statusEl.textContent = "Enter CUCM username and password (or use cached login) before searching.";
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
              const lookupStatusEl = document.getElementById("teams-remove-status");
              if (lookupStatusEl) {
                lookupStatusEl.textContent = "Selected " + uid + ". Running strict lookup...";
              }
              if (window.runTeamsRemoveLookup) {
                window.runTeamsRemoveLookup();
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
        if (!form || !statusEl || !outputEl || !deleteBtn) {
          return;
        }

        let state = window.teamsRemoveLookupState;
        if (!state || !state.match_found) {
          if (window.runTeamsRemoveLookup) {
            await window.runTeamsRemoveLookup();
            state = window.teamsRemoveLookupState;
          }
        }

        if (!state || !state.match_found) {
          alert("No strict match found. Run lookup and confirm MATCHED before deleting.");
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

    <h3>Reset Unity Voicemail PIN - with email notification</h3>

    <div class="secondary-layout">
      <form id="reset-pin-form" class="secondary-form" action="/reset/unity-voicemail-pin" method="post">
        Unity Admin Username:<br>
        <input name="unity_user" value="__AUTH_USER__" required><br><br>

        Unity Admin Password:<br>
        <input type="password" name="unity_pass" required><br><br>

        Voicemail Username to Reset PIN for:<br>
        <input name="voicemail_user" placeholder="john.doe" required><br><br>

        New Voicemail PIN (5 digits minimum):<br>
        <input type="password" name="new_voicemail_pin" placeholder="minimum 5 digits" required><br><br>

        Confirm New Voicemail PIN:<br>
        <input type="password" name="confirm_voicemail_pin" placeholder="minimum 5 digits" required><br><br>

        <div class="action-row">
          <button type="submit">Run Reset Unity Voicemail PIN - with email notification</button>
          <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
        </div>
      </form>

      <section class="secondary-output" aria-live="polite">
        <h4>Reset Voicemail PIN Output</h4>
        <p id="reset-pin-status" class="secondary-status">Run Reset Voicemail PIN to view output here.</p>
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
      <div class="compact-inline-row">
        <span>Last Name:</span>
        <input id="jabbernotify-last-name" placeholder="Smith" required>
      </div><br>
      <div class="compact-inline-row">
        <span>First Name (optional):</span>
        <input id="jabbernotify-first-name" placeholder="John">
      </div><br>
      <div class="action-row">
        <button type="submit">Search</button>
        +            <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
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
      <div class="action-row">
        <button type="submit">Send Mobile Instructions</button>
        <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
      </div>
    </form>
    <p id="mobile-jabber-notify-status" style="margin-top:14px; font-weight:700; min-height:18px;"></p>

    <hr style="margin:16px 0; border:none; border-top:1px solid #d6e4f3;">
    <p style="margin:0 0 10px 0; color:#355978;">Or lookup by name and send from the results:</p>
    <form id="mobile-jabber-lookup-form" class="jabber-check-form" style="max-width:520px;">
      <div class="compact-inline-row">
        <span>Cisco Callmanager Username:</span>
        <input name="cucm_user" value="__AUTH_USER__" required>
      </div><br>
      <div class="compact-inline-row">
        <span>Cisco Callmanager Password:</span>
        <input type="password" name="cucm_pass" required>
      </div><br>
      <div class="compact-inline-row">
        <span>Last Name:</span>
        <input id="mobile-jabber-last-name" name="last_name" placeholder="Smith" required>
      </div><br>
      <div class="compact-inline-row">
        <span>First Name (optional):</span>
        <input id="mobile-jabber-first-name" name="first_name" placeholder="John">
      </div><br>
      <div class="action-row">
        <button type="submit">Search</button>
        <span class="env-action-pill __ENV_CLASS__">__ENV_TEXT__</span>
      </div>
    </form>
    <p id="mobile-jabber-lookup-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
    <div id="mobile-jabber-lookup-results" style="overflow-x:auto; margin-top:8px;"></div>
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
      const hasCachedCucmPassword = __HAS_CACHED_CUCM_PASS__;
      const hasCachedUnityPassword = __HAS_CACHED_UNITY_PASS__;
      const credentialExpiresAtMs = __CREDENTIAL_EXPIRES_AT_MS__;

      const sessionTimerBanner = document.getElementById("session-timer-banner");
      const sessionTimerRemaining = document.getElementById("session-timer-remaining");

      function formatTimerValue(totalSeconds) {
        const safe = Math.max(0, Math.floor(totalSeconds));
        const hours = Math.floor(safe / 3600);
        const minutes = Math.floor((safe % 3600) / 60);
        const seconds = safe % 60;
        return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
      }

      function startCredentialTimer() {
        if (!hasCachedCucmPassword || !sessionTimerBanner || !sessionTimerRemaining || !credentialExpiresAtMs) {
          return;
        }

        sessionTimerBanner.style.display = "flex";

        const updateTimer = () => {
          const remainingMs = credentialExpiresAtMs - Date.now();
          if (remainingMs <= 0) {
            sessionTimerRemaining.textContent = "Expired";
            window.location.href = "/logout";
            return;
          }
          sessionTimerRemaining.textContent = formatTimerValue(remainingMs / 1000);
        };

        updateTimer();
        window.setInterval(updateTimer, 1000);
      }

      startCredentialTimer();

      function hideCachedCredentialFields() {
        if (!hasCachedCucmPassword) {
          return;
        }

        document.querySelectorAll('input[name="cucm_user"], input[name="cucm_pass"]').forEach((inputEl) => {
          inputEl.required = false;
          if (inputEl.name === "cucm_pass") {
            inputEl.value = "";
            inputEl.placeholder = "Using cached password (expires in 60 minutes)";
          }

          const row = inputEl.closest(".compact-inline-row");
          if (row) {
            row.style.display = "none";
          }

          if (inputEl.name === "cucm_pass") {
            inputEl.style.display = "none";
            let prev = inputEl.previousSibling;
            while (prev) {
              if (prev.nodeType === Node.TEXT_NODE && (prev.textContent || "").toLowerCase().includes("callmanager password")) {
                prev.textContent = "";
              }
              if (prev.nodeType === Node.ELEMENT_NODE && prev.tagName === "BR") {
                prev.style.display = "none";
              }
              prev = prev.previousSibling;
            }
          }
        });

        if (hasCachedUnityPassword) {
          document.querySelectorAll('input[name="unity_user"], input[name="unity_pass"]').forEach((inputEl) => {
            inputEl.required = false;
            if (inputEl.name === "unity_pass") {
              inputEl.value = "";
              inputEl.placeholder = "Using cached password (expires in 60 minutes)";
            }

            const row = inputEl.closest(".compact-inline-row");
            if (row) {
              row.style.display = "none";
            }

            if (inputEl.name === "unity_user") {
              inputEl.style.display = "none";
              let prev = inputEl.previousSibling;
              while (prev) {
                if (prev.nodeType === Node.TEXT_NODE && (prev.textContent || "").toLowerCase().includes("unity admin username")) {
                  prev.textContent = "";
                }
                if (prev.nodeType === Node.ELEMENT_NODE && prev.tagName === "BR") {
                  prev.style.display = "none";
                }
                prev = prev.previousSibling;
              }
            }

            if (inputEl.name === "unity_pass") {
              inputEl.style.display = "none";
              let prev = inputEl.previousSibling;
              while (prev) {
                if (prev.nodeType === Node.TEXT_NODE && (prev.textContent || "").toLowerCase().includes("unity admin password")) {
                  prev.textContent = "";
                }
                if (prev.nodeType === Node.ELEMENT_NODE && prev.tagName === "BR") {
                  prev.style.display = "none";
                }
                prev = prev.previousSibling;
              }
            }
          });
        }
      }

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
          pattern: /^\\d{5,20}$/,
          patternMessage: "Voicemail PIN must be numeric and 5-20 digits.",
        },
        confirm_voicemail_pin: {
          required: true,
          requiredMessage: "Confirm Voicemail PIN is required.",
          pattern: /^\\d{5,20}$/,
          patternMessage: "Voicemail PIN must be numeric and 5-20 digits.",
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

      if (hasCachedCucmPassword) {
        fieldRules.cucm_pass.required = false;
      }
      if (hasCachedUnityPassword) {
        fieldRules.unity_user.required = false;
        fieldRules.unity_pass.required = false;
      }

      hideCachedCredentialFields();

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

          // Skip hidden inputs — they are filled programmatically, not by the user.
          if (field.type === "hidden") {
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

        statusEl.textContent = "Running Reset Voicemail PIN...";
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
          if (result.email_status) {
            statusEl.textContent += " — " + result.email_status;
          }
          downloadEl.href = result.download_url;
          downloadEl.style.display = "inline";

          const voicemailUserInput = form.querySelector('input[name="voicemail_user"]');
          const newPinInput = form.querySelector('input[name="new_voicemail_pin"]');
          const confirmPinInput = form.querySelector('input[name="confirm_voicemail_pin"]');
          if (voicemailUserInput) voicemailUserInput.value = "";
          if (newPinInput) newPinInput.value = "";
          if (confirmPinInput) confirmPinInput.value = "";
        } catch (error) {
          statusEl.textContent = "Reset Voicemail PIN failed. Review output and retry.";
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
          if (!cucmUser || (!cucmPass && !hasCachedCucmPassword)) { jnStatus.textContent = "Enter CUCM username and password (or use cached login) first."; return; }
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
            jnStatus.textContent = "Found " + results.length + " user(s). Click Send New Jabber Email to email a user.";
            var html = '<table style="width:100%; border-collapse:collapse; font-size:13px;"><thead><tr style="background:#005eb8; color:#fff;">';
            html += '<th style="padding:8px 10px; text-align:left;">Name</th><th style="padding:8px 10px; text-align:left;">User ID</th><th style="padding:8px 10px; text-align:left;">Telephone</th><th style="padding:8px 10px; text-align:left;">Email</th><th style="padding:8px 10px; text-align:left;">Action</th></tr></thead><tbody>';
            results.forEach(function (r, i) {
              var bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
              var uid = r.userid || "";
              var name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || uid;
              var tel = r.telephone || "\u2014";
              var email = r.email || "\u2014";
              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;"><td style="padding:7px 10px;">' + name + '</td><td style="padding:7px 10px;">' + uid + '</td><td style="padding:7px 10px;">' + tel + '</td><td style="padding:7px 10px;">' + email + '</td><td style="padding:7px 10px;"><button type="button" data-nuid="' + uid + '" data-ntel="' + (r.telephone || "") + '" style="background:#237741;color:#fff;border:none;border-radius:6px;padding:6px 12px;font-weight:700;cursor:pointer;">Send New Jabber Email</button></td></tr>';
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
        var lookupForm = document.getElementById("mobile-jabber-lookup-form");
        var lookupStatusEl = document.getElementById("mobile-jabber-lookup-status");
        var lookupResultsEl = document.getElementById("mobile-jabber-lookup-results");
        if (!form || !statusEl) return;

        function getApiErrorMessage(payload, fallbackMessage) {
          if (!payload) return fallbackMessage;
          if (typeof payload.detail === "string" && payload.detail.trim()) {
            return payload.detail.trim();
          }
          if (payload.error && typeof payload.error.message === "string" && payload.error.message.trim()) {
            return payload.error.message.trim();
          }
          return fallbackMessage;
        }

        form.addEventListener("submit", async function (event) {
          event.preventDefault();
          var userField = form.querySelector('input[name="cucm_user"]');
          var passField = form.querySelector('input[name="cucm_pass"]');
          var targetField = form.querySelector('input[name="target_user"]');
          var cucmUser = ((userField && userField.value) || "").trim();
          var cucmPass = (passField && passField.value) || "";
          var targetUser = ((targetField && targetField.value) || "").trim();

          if (!cucmUser || (!cucmPass && !hasCachedCucmPassword)) {
            statusEl.textContent = "Enter CUCM username and password (or use cached login) first.";
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
            var resp = await fetch("/send/mobile-jabber-email", {
              method: "POST",
              body: fd,
              credentials: "same-origin",
              headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
            });
            var payload = await resp.json();
            if (!resp.ok || !payload.ok) {
              throw new Error(getApiErrorMessage(payload, "Send failed."));
            }
            statusEl.textContent = "Sent: " + (payload.detail || "Mobile email sent successfully.");
          } catch (err) {
            statusEl.textContent = "Failed: " + ((err && err.message) || "Unknown error.");
          }
        });

        if (lookupForm && lookupStatusEl && lookupResultsEl) {
          lookupForm.addEventListener("submit", async function (event) {
            event.preventDefault();
            lookupStatusEl.textContent = "Searching...";
            lookupResultsEl.innerHTML = "";

            var userField = lookupForm.querySelector('input[name="cucm_user"]');
            var passField = lookupForm.querySelector('input[name="cucm_pass"]');
            var lastNameField = lookupForm.querySelector('input[name="last_name"]');
            var firstNameField = lookupForm.querySelector('input[name="first_name"]');
            var cucmUser = ((userField && userField.value) || "").trim();
            var cucmPass = (passField && passField.value) || "";
            var lastName = ((lastNameField && lastNameField.value) || "").trim();
            var firstName = ((firstNameField && firstNameField.value) || "").trim();

            if (!cucmUser || (!cucmPass && !hasCachedCucmPassword)) {
              lookupStatusEl.textContent = "Enter CUCM username and password (or use cached login) first.";
              return;
            }
            if (!lastName) {
              lookupStatusEl.textContent = "Last Name is required.";
              return;
            }

            try {
              var fd = new FormData();
              fd.append("cucm_user", cucmUser);
              fd.append("cucm_pass", cucmPass);
              fd.append("last_name", lastName);
              fd.append("first_name", firstName);
              var resp = await fetch("/lookup/person", {
                method: "POST",
                body: fd,
                credentials: "same-origin",
                headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
              });
              var payload = await resp.json();
              if (!resp.ok || !payload.ok) {
                throw new Error(getApiErrorMessage(payload, "Search failed."));
              }

              var results = payload.results || [];
              if (!results.length) {
                lookupStatusEl.textContent = "No users found.";
                return;
              }

              lookupStatusEl.textContent = "Found " + results.length + " user(s). Click Send Mobile Email.";
              var html = '<table style="width:100%; border-collapse:collapse; font-size:13px;"><thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left;">Name</th>';
              html += '<th style="padding:8px 10px; text-align:left;">User ID</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Telephone</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Email</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Action</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                var bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                var uid = r.userid || "";
                var name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || uid;
                var tel = r.telephone || "\u2014";
                var email = r.email || "\u2014";
                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px;">' + tel + '</td>';
                html += '<td style="padding:7px 10px;">' + email + '</td>';
                html += '<td style="padding:7px 10px;"><button type="button" data-mobile-notify-uid="' + uid + '" data-mobile-notify-tel="' + (r.telephone || "") + '" style="background:#0f766e;color:#fff;border:none;border-radius:6px;padding:6px 12px;font-weight:700;cursor:pointer;">Send Mobile Email</button></td>';
                html += '</tr>';
              });
              html += '</tbody></table>';
              lookupResultsEl.innerHTML = html;

              lookupResultsEl.querySelectorAll('button[data-mobile-notify-uid]').forEach(function (btn) {
                btn.addEventListener("click", async function () {
                  var uid = btn.getAttribute("data-mobile-notify-uid") || "";
                  var tel = btn.getAttribute("data-mobile-notify-tel") || "";
                  btn.disabled = true;
                  lookupStatusEl.textContent = "Sending...";
                  try {
                    var sf = new FormData();
                    sf.append("cucm_user", cucmUser);
                    sf.append("cucm_pass", cucmPass);
                    sf.append("target_user", uid);
                    sf.append("telephone", tel);
                    var sr = await fetch("/send/mobile-jabber-email", {
                      method: "POST",
                      body: sf,
                      credentials: "same-origin",
                      headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                    });
                    var sp = await sr.json();
                    if (!sr.ok || !sp.ok) {
                      throw new Error(getApiErrorMessage(sp, "Send failed."));
                    }
                    lookupStatusEl.textContent = "Sent: " + (sp.detail || "Mobile email sent successfully.");
                  } catch (err) {
                    lookupStatusEl.textContent = "Failed: " + ((err && err.message) || "Unknown error.");
                    btn.disabled = false;
                  }
                });
              });
            } catch (err) {
              lookupStatusEl.textContent = "Search error: " + ((err && err.message) || "Unknown error.");
            }
          });
        }
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

      function applyPanelPrefill(panel, userId, telephone) {
        if (!panel) return;
        ['input[name="target_user"]', 'input[name="voicemail_user"]'].forEach((selector) => {
          const field = panel.querySelector(selector);
          if (field) {
            field.value = userId || "";
          }
        });

        const telephoneField = panel.querySelector('input[name="telephone"]');
        if (telephoneField) {
          telephoneField.value = telephone || "";
        }
      }

      // Globally accessible so inline onclick handlers in dynamic tables can call it.
      window.prefillPanel = function (panelKey, userId, telephone) {
        showPanel(panelKey);
        const panel = panels.find((p) => p.dataset.panel === panelKey);
        if (!panel) return;
        applyPanelPrefill(panel, userId, telephone);
        // Scroll panel into view
        panel.scrollIntoView({ behavior: "smooth", block: "start" });
      };

      window.prefillMobileJabberNotify = function (userId, telephone) {
        showPanel("mobilejabbernotify");
        var userField = document.getElementById("mobile-jabber-target-user");
        if (userField) userField.value = userId || "";
        var panel = panels.find((p) => p.dataset.panel === "mobilejabbernotify");
        if (panel) {
          panel.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      };

      navButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
          const panelKey = (btn.dataset.panel || "").trim();
          if (!panelKey) {
            return;
          }
          showPanel(panelKey);
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
          applyPanelPrefill(targetPanel, initialTargetUser, "");
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
""".replace("__AUTH_USER__", auth_user).replace("__AUTH_CUCM_HOST__", escape(auth_cucm_host)).replace("__ENV_TEXT__", escape(env_text)).replace("__ENV_CLASS__", env_css_class).replace("__ADMIN_CARD__", admin_card_html).replace("__HAS_CACHED_CUCM_PASS__", "true" if has_cached_cucm_pass else "false").replace("__HAS_CACHED_UNITY_PASS__", "true" if has_cached_unity_pass else "false").replace("__CREDENTIAL_EXPIRES_AT_MS__", str(credential_expires_at_ms))

  return HTMLResponse(
    content=html,
    headers={
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "Pragma": "no-cache",
      "Expires": "0",
    },
  )


@app.get("/page4", response_class=HTMLResponse)
def page4_certificate_manager(request: Request):
  session = _get_auth_session(request) or {}
  now_epoch = time.time()
  session_username = str(session.get("username", ""))
  if not _is_admin_user(session_username):
    return HTMLResponse(
      content="<h3>403 Forbidden</h3><p>You are not authorized to access Server Certificate Manager.</p>",
      status_code=403,
    )

  auth_user = escape(session_username)
  auth_cucm_host = str(session.get("cucm_host", "") or "")
  cert_manager_enabled = _feature_enabled(
    CERT_MANAGER_PAGE_ENABLED,
    lab_only=(CERT_MANAGER_PAGE_LAB_ONLY and PREVIEW_FEATURES_LAB_ONLY_DEFAULT),
    cucm_host=auth_cucm_host,
  )
  if not cert_manager_enabled or not _is_lab_environment(auth_cucm_host):
    return HTMLResponse(
      content="<h3>403 Forbidden</h3><p>Server Certificate Manager is LAB-only and disabled in this environment.</p>",
      status_code=403,
    )

  has_cached_cucm_pass = _has_valid_cached_secret(session, "cucm_pass", now_epoch)
  if not has_cached_cucm_pass:
    page4_sid = request.cookies.get(SESSION_COOKIE_NAME, "")
    if page4_sid:
      has_cached_cucm_pass = bool((AUTH_SESSION_SECRETS.get(page4_sid, {}).get("cucm_pass", "") or "").strip())
  credential_expires_at = float(session.get("credential_expires_at", 0) or 0)
  credential_expires_at_ms = int(credential_expires_at * 1000) if (has_cached_cucm_pass and credential_expires_at > 0) else 0
  env_text, env_css_class = _get_environment_label(auth_cucm_host)

  html = """
<html>
  <head>
    <title>Server Certificate Manager - Voice Operations Portal</title>
    <style>
      body {
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        margin: 0;
        background: linear-gradient(180deg, #f7fbff 0%, #edf5fc 100%);
        color: #12304a;
      }
      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 10px 16px;
        background: linear-gradient(120deg, rgba(0, 47, 108, 0.98), rgba(0, 94, 184, 0.94));
        color: #fff;
      }
      .topbar-actions a {
        color: #fff;
        text-decoration: none;
        margin-left: 10px;
        font-weight: 700;
      }
      .env-banner {
        display: inline-block;
        padding: 6px 10px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.35);
        font-size: 11px;
        font-weight: 700;
      }
      .content {
        max-width: 1300px;
        margin: 10px auto;
        padding: 0 14px 16px 14px;
      }
      .panel {
        background: #fff;
        border-radius: 12px;
        border: 1px solid rgba(0, 47, 108, 0.12);
        box-shadow: 0 10px 24px rgba(0, 47, 108, 0.11);
        padding: 14px;
        margin-bottom: 12px;
      }
      .preview-banner {
        margin: 0 0 10px 0;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid #d97706;
        background: #fff4e5;
        color: #8a4b00;
        font-weight: 700;
      }
      .danger-banner {
        margin: 0;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid #dc2626;
        background: #fef2f2;
        color: #991b1b;
        font-weight: 700;
      }
      .toolbar {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 12px;
      }
      .inventory-controls {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 10px;
        margin-top: 12px;
      }
      .inventory-controls label {
        display: block;
        font-size: 12px;
        font-weight: 700;
        color: #2c5c8a;
        margin-bottom: 4px;
      }
      .inventory-controls input,
      .inventory-controls select {
        width: 100%;
        border: 1px solid #b7d0eb;
        border-radius: 8px;
        padding: 8px 10px;
        font-size: 13px;
        box-sizing: border-box;
      }
      .toolbar button,
      .toolbar a {
        display: inline-block;
        background: #005eb8;
        color: #fff;
        border: 1px solid #005eb8;
        border-radius: 8px;
        padding: 8px 12px;
        font-size: 13px;
        font-weight: 700;
        text-decoration: none;
        cursor: pointer;
      }
      .toolbar a {
        background: #fff;
        color: #005eb8;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
      }
      th {
        background: #005eb8;
        color: #fff;
        text-align: left;
        padding: 8px;
        white-space: nowrap;
      }
      td {
        border-bottom: 1px solid #d5e4f5;
        padding: 8px;
        vertical-align: top;
      }
      .mono {
        font-family: Consolas, "Courier New", monospace;
      }
      .status-ok {
        color: #047857;
        font-weight: 700;
      }
      .status-warn {
        color: #b45309;
        font-weight: 700;
      }
      .status-bad {
        color: #b91c1c;
        font-weight: 700;
      }
      .run-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 10px;
        margin-top: 10px;
      }
      .run-grid textarea {
        width: 100%;
        min-height: 120px;
        border: 1px solid #b7d0eb;
        border-radius: 8px;
        padding: 8px;
        font-family: Consolas, "Courier New", monospace;
        font-size: 12px;
        box-sizing: border-box;
      }
      .run-pill {
        display: inline-block;
        padding: 5px 8px;
        border-radius: 999px;
        border: 1px solid #93c5fd;
        background: #eff6ff;
        color: #1d4ed8;
        font-size: 12px;
        font-weight: 700;
      }
      .debug-window {
        width: 100%;
        min-height: 180px;
        border: 1px solid #b7d0eb;
        border-radius: 8px;
        padding: 8px;
        box-sizing: border-box;
        font-family: Consolas, "Courier New", monospace;
        font-size: 12px;
        background: #f8fbff;
      }
    </style>
  </head>
  <body>
    <header class="topbar">
      <div><strong>Voice Operations Portal</strong> - Server Certificate Manager</div>
      <div>
        <span class="env-banner __ENV_CLASS__">__ENV_TEXT__</span>
      </div>
      <div class="topbar-actions">
        <a href="/menu-admin">Administrative Items</a>
        <a href="/logout">Log Out</a>
      </div>
    </header>

    <main class="content">
      <section class="panel">
        <h3 style="margin-top:0;">Quick Overview</h3>
        <p id="cert-inventory-status" style="margin-top:4px; color:#2c5c8a;">Loading inventory...</p>
        <div id="cert-quick-results" style="overflow-x:auto; margin-bottom:10px;"></div>
      </section>

      <section class="panel">
        <h3 style="margin-top:0;">Deep Dive Inventory Lookup</h3>
        <p class="preview-banner">LAB-only preview: read-only certificate inventory for CUCM, IM and Presence, and Unity Voicemail.</p>
        <p class="danger-banner">Full server restart is not part of this tool and is intentionally blocked by design.</p>
        <p>Authenticated Operator: <strong>__AUTH_USER__</strong></p>
        <form method="post" action="/cert-manager/lab/inventory-sync" style="margin:8px 0 10px 0;">
          <button type="submit" style="background:#0b6bcb;color:#fff;border:1px solid #0b6bcb;border-radius:8px;padding:7px 10px;font-weight:700;cursor:pointer;">Run Inventory (No-JS Fallback)</button>
          <span style="margin-left:8px;color:#4e6a84;font-size:12px;">Use this if page buttons appear stuck.</span>
        </form>
        <form id="deep-inventory-form" method="post" action="/cert-manager/lab/inventory-sync">
        <div class="inventory-controls">
          <div>
            <label for="target-host">Target System(s)</label>
              <select id="target-host" name="target_hosts" multiple size="7">
              __TARGET_OPTIONS__
            </select>
          </div>
          <div>
            <label for="platform-user">Platform Username (optional override)</label>
            <input id="platform-user" name="platform_user" type="text" placeholder="Use cached login if left blank" autocomplete="username" />
          </div>
          <div>
            <label for="platform-pass">Platform Password (optional override)</label>
            <input id="platform-pass" name="platform_pass" type="password" placeholder="Use cached login if left blank" autocomplete="current-password" />
          </div>
        </div>
        <div class="toolbar">
          <button id="refresh-inventory-btn" type="submit">Refresh Inventory</button>
          <a href="/ops/parity-report" target="_blank" rel="noopener">Open Parity Report JSON</a>
        </div>
        </form>
        <h4 style="margin:12px 0 6px 0;">Certificates Expiring in 45 Days or Less</h4>
        <div id="cert-inventory-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel">
        <h3 style="margin-top:0;">Renewal Run (2-Server Workflow)</h3>
        <p style="margin:0 0 8px 0; color:#2c5c8a;">Create one run for your two target servers, then execute steps in order.</p>
        <p><span class="run-pill" id="renewal-run-id">Run: not started</span></p>
        <div class="toolbar">
          <button id="renewal-create-run-btn" type="button">Create Renewal Run</button>
          <button id="renewal-precheck-btn" type="button">1) Run Precheck</button>
          <button id="renewal-generate-csr-btn" type="button">2) Generate CSR</button>
          <button id="renewal-download-csr-btn" type="button">Download CSR Bundle</button>
          <button id="renewal-upload-btn" type="button">3) Upload Signed Certificate</button>
          <button id="renewal-restart-btn" type="button">4) Restart Services</button>
          <button id="renewal-validate-btn" type="button">5) Final Validate</button>
        </div>
        <div class="run-grid">
          <div>
            <label for="renewal-cert-alias" style="display:block;font-weight:700;margin-bottom:4px;">Certificate Alias</label>
            <input id="renewal-cert-alias" type="text" value="tomcat" style="width:100%;border:1px solid #b7d0eb;border-radius:8px;padding:8px 10px;box-sizing:border-box;" />
          </div>
          <div style="grid-column: 1 / -1;">
            <label for="renewal-signed-chain" style="display:block;font-weight:700;margin-bottom:4px;">Signed Certificate Chain (PEM)</label>
            <textarea id="renewal-signed-chain" placeholder="Paste CA-signed leaf + intermediates + root PEM bundle here"></textarea>
          </div>
        </div>
        <h4 style="margin:12px 0 6px 0;">Run Status</h4>
        <div id="renewal-run-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel">
        <h3 style="margin-top:0;">Debug Window</h3>
        <p style="margin:0 0 8px 0; color:#2c5c8a;">Use this for quick copy/paste when reporting issues.</p>
        <div class="toolbar" style="margin-top:0;">
          <button id="debug-copy-btn" type="button">Copy Debug Log</button>
          <button id="debug-clear-btn" type="button">Clear Debug Log</button>
        </div>
        <textarea id="debug-log" class="debug-window" readonly>Debug window initialized. If this never updates after load, page JavaScript failed before startup.</textarea>
        <noscript><p style="color:#b91c1c;font-weight:700;">JavaScript is disabled; Page4 interactive actions will not run.</p></noscript>
      </section>
    </main>

    <script>
      (function () {
        const hasCachedCucmPass = "__HAS_CACHED_CUCM_PASS__" === "true";
        const credentialExpiresAtMs = Number("__CREDENTIAL_EXPIRES_AT_MS__") || 0;

        const statusEl = document.getElementById("cert-inventory-status");
        const quickResultsEl = document.getElementById("cert-quick-results");
        const resultsEl = document.getElementById("cert-inventory-results");
        const deepInventoryFormEl = document.getElementById("deep-inventory-form");
        const refreshBtn = document.getElementById("refresh-inventory-btn");
        const targetHostEl = document.getElementById("target-host");
        const platformUserEl = document.getElementById("platform-user");
        const platformPassEl = document.getElementById("platform-pass");
        const renewalRunIdEl = document.getElementById("renewal-run-id");
        const renewalResultsEl = document.getElementById("renewal-run-results");
        const renewalAliasEl = document.getElementById("renewal-cert-alias");
        const renewalSignedChainEl = document.getElementById("renewal-signed-chain");
        const renewalCreateRunBtn = document.getElementById("renewal-create-run-btn");
        const renewalPrecheckBtn = document.getElementById("renewal-precheck-btn");
        const renewalGenerateCsrBtn = document.getElementById("renewal-generate-csr-btn");
        const renewalDownloadCsrBtn = document.getElementById("renewal-download-csr-btn");
        const renewalUploadBtn = document.getElementById("renewal-upload-btn");
        const renewalRestartBtn = document.getElementById("renewal-restart-btn");
        const renewalValidateBtn = document.getElementById("renewal-validate-btn");
        const debugLogEl = document.getElementById("debug-log");
        const debugCopyBtn = document.getElementById("debug-copy-btn");
        const debugClearBtn = document.getElementById("debug-clear-btn");
        let currentRenewalRunId = "";
        let currentRenewalRun = null;

        function debugNow() {
          try { return new Date().toISOString(); } catch (_e) { return ""; }
        }

        function appendDebug(message) {
          if (!debugLogEl) return;
          const line = "[" + debugNow() + "] " + String(message || "");
          debugLogEl.value = (debugLogEl.value ? (debugLogEl.value + "\n") : "") + line;
          debugLogEl.scrollTop = debugLogEl.scrollHeight;
        }

        function toCell(value) {
          if (value === null || value === undefined || value === "") return "-";
          return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/\"/g, "&quot;")
            .replace(/'/g, "&#39;");
        }

        function statusClass(row) {
          const days = Number(row.days_remaining);
          const statusText = String(row.status || "").toLowerCase();
          if (statusText.includes("fetch failed") || statusText.includes("error")) return "status-bad";
          if (!Number.isNaN(days) && days >= 0 && days <= 30) return "status-warn";
          if (!Number.isNaN(days) && days < 0) return "status-bad";
          return "status-ok";
        }

        function render(rows) {
          if (!Array.isArray(rows) || !rows.length) {
            resultsEl.innerHTML = "<p>Select one or more target hosts, then click Refresh Inventory for deep lookup results.</p>";
            return;
          }

          const sortedRows = rows.slice().sort(function (a, b) {
            const aDays = Number(a.days_remaining);
            const bDays = Number(b.days_remaining);
            const aVal = Number.isNaN(aDays) ? Number.POSITIVE_INFINITY : aDays;
            const bVal = Number.isNaN(bDays) ? Number.POSITIVE_INFINITY : bDays;
            return aVal - bVal;
          });

          const expiringRows = sortedRows.filter(function (row) {
            const days = Number(row.days_remaining);
            return !Number.isNaN(days) && days <= 45;
          });

          if (!expiringRows.length) {
            resultsEl.innerHTML = "<p style='margin:0; color:#047857; font-weight:700;'>No certificates expiring within 45 days.</p>";
            return;
          }

          let html = "<table><thead><tr>";
          html += "<th>System</th><th>Certificate</th><th>Common Name</th><th>Usage</th><th>Type</th><th>Expiration Date</th><th>Days Left</th><th>Status</th>";
          html += "</tr></thead><tbody>";

          expiringRows.forEach(function (row) {
            const cls = statusClass(row);
            html += "<tr>";
            html += "<td>" + toCell(row.system) + "</td>";
            html += "<td class='mono'>" + toCell(row.certificate) + "</td>";
            html += "<td class='mono'>" + toCell(row.common_name) + "</td>";
            html += "<td>" + toCell(row.usage) + "</td>";
            html += "<td>" + toCell(row.type) + "</td>";
            html += "<td class='mono'>" + toCell(row.expiration_date) + "</td>";
            html += "<td>" + toCell(row.days_remaining) + "</td>";
            html += "<td class='" + cls + "'>" + toCell(row.status) + "</td>";
            html += "</tr>";
          });

          html += "</tbody></table>";
          resultsEl.innerHTML = html;
        }

        function renderQuick(rows) {
          if (!Array.isArray(rows) || !rows.length) {
            quickResultsEl.innerHTML = "<p>No quick overview rows returned.</p>";
            return;
          }

          let html = "<table><thead><tr>";
          html += "<th>System</th><th>Certificate</th><th>Expiration Date</th><th>Days Left</th><th>Valid Until (UTC)</th><th>Common Name</th><th>Status</th>";
          html += "</tr></thead><tbody>";

          rows.forEach(function (row) {
            const cls = statusClass(row);
            html += "<tr>";
            html += "<td>" + toCell(row.system) + "</td>";
            html += "<td class='mono'>" + toCell(row.certificate) + "</td>";
            html += "<td class='mono'>" + toCell(row.expiration_date_short || row.expiration_date) + "</td>";
            html += "<td>" + toCell(row.days_remaining) + "</td>";
            html += "<td class='mono'>" + toCell(row.expiration_date) + "</td>";
            html += "<td class='mono'>" + toCell(row.common_name) + "</td>";
            html += "<td class='" + cls + "'>" + toCell(row.status) + "</td>";
            html += "</tr>";
          });

          html += "</tbody></table>";
          quickResultsEl.innerHTML = html;
        }

        function selectedHosts() {
          return targetHostEl
            ? Array.from(targetHostEl.selectedOptions || []).map(function (opt) {
                return (opt && opt.value ? opt.value : "").trim();
              }).filter(Boolean)
            : [];
        }

        function credentialsPayload() {
          return {
            platform_user: (platformUserEl && platformUserEl.value ? platformUserEl.value : "").trim(),
            platform_pass: (platformPassEl && platformPassEl.value ? platformPassEl.value : "").trim(),
          };
        }

        function renderRenewalRun(run) {
          if (!run || !run.hosts) {
            renewalResultsEl.innerHTML = "<p>No renewal run yet.</p>";
            return;
          }
          currentRenewalRun = run;
          currentRenewalRunId = run.run_id || "";
          renewalRunIdEl.textContent = currentRenewalRunId ? ("Run: " + currentRenewalRunId) : "Run: not started";

          let html = "<table><thead><tr><th>Host</th><th>Precheck</th><th>Generate CSR</th><th>Upload Cert</th><th>Restart</th><th>Final Validate</th></tr></thead><tbody>";
          Object.keys(run.hosts || {}).forEach(function (host) {
            const hostObj = run.hosts[host] || {};
            const steps = hostObj.steps || {};
            function stepCell(stepKey) {
              const step = steps[stepKey] || {};
              const st = String(step.status || "pending");
              const detail = String(step.detail || "");
              const cls = st === "ok" ? "status-ok" : (st === "failed" ? "status-bad" : (st === "warning" ? "status-warn" : ""));
              return "<td class='" + cls + "'>" + toCell(st + (detail ? (": " + detail) : "")) + "</td>";
            }
            html += "<tr>";
            html += "<td class='mono'>" + toCell(host) + "</td>";
            html += stepCell("precheck");
            html += stepCell("generate_csr");
            html += stepCell("upload_signed_cert");
            html += stepCell("restart_services");
            html += stepCell("final_validate");
            html += "</tr>";
          });
          html += "</tbody></table>";
          renewalResultsEl.innerHTML = html;
        }

        async function createRenewalRun() {
          const hosts = selectedHosts();
          appendDebug("createRenewalRun: selected_hosts=" + hosts.join(","));
          if (hosts.length !== 2) {
            alert("Select exactly 2 target hosts to create a renewal run.");
            appendDebug("createRenewalRun blocked: expected 2 hosts, got " + hosts.length);
            return;
          }
          const started = Date.now();
          const response = await fetch("/cert-manager/lab/renewal/run/create", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_hosts: hosts }),
          });
          const payload = await response.json();
          appendDebug("createRenewalRun response: status=" + response.status + " elapsed_ms=" + (Date.now() - started));
          if (!response.ok || !payload.ok) {
            appendDebug("createRenewalRun error: " + ((payload && payload.detail) || "unknown"));
            throw new Error((payload && payload.detail) || "Failed to create renewal run.");
          }
          appendDebug("createRenewalRun success: run_id=" + String((payload.run || {}).run_id || ""));
          renderRenewalRun(payload.run || null);
        }

        async function runRenewalAction(actionName) {
          appendDebug("runRenewalAction: action=" + actionName + " run_id=" + currentRenewalRunId);
          if (!currentRenewalRunId) {
            alert("Create a renewal run first.");
            appendDebug("runRenewalAction blocked: no run_id");
            return;
          }
          const creds = credentialsPayload();
          if ((!hasCachedCucmPass || !credentialExpiresAtMs) && (!creds.platform_user || !creds.platform_pass)) {
            alert("Provide Platform Username and Platform Password.");
            appendDebug("runRenewalAction blocked: missing credentials");
            return;
          }
          const started = Date.now();
          const response = await fetch("/cert-manager/lab/renewal/run/" + encodeURIComponent(currentRenewalRunId) + "/action", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              action: actionName,
              cert_alias: (renewalAliasEl && renewalAliasEl.value ? renewalAliasEl.value : "tomcat").trim() || "tomcat",
              signed_chain_pem: (renewalSignedChainEl && renewalSignedChainEl.value ? renewalSignedChainEl.value : "").trim(),
              platform_user: creds.platform_user,
              platform_pass: creds.platform_pass,
            }),
          });
          const payload = await response.json();
          appendDebug("runRenewalAction response: action=" + actionName + " status=" + response.status + " elapsed_ms=" + (Date.now() - started));
          if (!response.ok || !payload.ok) {
            appendDebug("runRenewalAction error: " + ((payload && payload.detail) || "unknown"));
            throw new Error((payload && payload.detail) || "Renewal action failed.");
          }
          appendDebug("runRenewalAction success: action=" + actionName);
          renderRenewalRun(payload.run || null);
        }

        function downloadCsrBundle() {
          if (!currentRenewalRun || !currentRenewalRun.hosts) {
            alert("No CSR data available yet.");
            return;
          }
          const lines = [];
          Object.keys(currentRenewalRun.hosts).forEach(function (host) {
            const hostState = currentRenewalRun.hosts[host] || {};
            const csr = String(hostState.csr_pem || "").trim();
            if (!csr) return;
            lines.push("### " + host);
            lines.push(csr);
            lines.push("");
          });
          if (!lines.length) {
            alert("No CSR generated yet. Run 'Generate CSR' first.");
            return;
          }
          const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "renewal-csr-bundle.txt";
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
        }

        async function loadInventory() {
          const opStarted = Date.now();
          let progressTimer = null;
          if (refreshBtn) {
            refreshBtn.disabled = true;
            refreshBtn.textContent = "Refreshing...";
          }
          statusEl.textContent = "Starting refresh request...";
          const payloadBody = {
            target_hosts: (targetHostEl ? Array.from(targetHostEl.selectedOptions || []).map(function (opt) { return (opt && opt.value ? opt.value : "").trim(); }).filter(Boolean) : []),
            platform_user: (platformUserEl && platformUserEl.value ? platformUserEl.value : "").trim(),
            platform_pass: (platformPassEl && platformPassEl.value ? platformPassEl.value : "").trim(),
          };
          appendDebug("loadInventory start: targets=" + payloadBody.target_hosts.join(",") + " user_override=" + (payloadBody.platform_user ? "yes" : "no"));

          progressTimer = setInterval(function () {
            const sec = Math.max(0, Math.floor((Date.now() - opStarted) / 1000));
            statusEl.textContent = "Refreshing inventory... " + sec + "s elapsed";
          }, 1000);

          if ((!hasCachedCucmPass || !credentialExpiresAtMs) && (!payloadBody.platform_user || !payloadBody.platform_pass)) {
            statusEl.textContent = "Inventory requires credentials: enter Platform Username and Platform Password.";
            resultsEl.innerHTML = "";
            appendDebug("loadInventory blocked: missing credentials");
            if (progressTimer) clearInterval(progressTimer);
            if (refreshBtn) {
              refreshBtn.disabled = false;
              refreshBtn.textContent = "Refresh Inventory";
            }
            return;
          }

          try {
            const started = Date.now();
            statusEl.textContent = "Submitting request to /cert-manager/lab/inventory ...";
            const response = await fetch("/cert-manager/lab/inventory", {
              method: "POST",
              credentials: "same-origin",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify(payloadBody),
            });
            const payload = await response.json();
            appendDebug("loadInventory response: status=" + response.status + " elapsed_ms=" + (Date.now() - started));
            if (!response.ok || !payload.ok) {
              appendDebug("loadInventory error payload: " + ((payload && payload.detail) || "unknown"));
              throw new Error((payload && payload.detail) || "Failed to load certificate inventory.");
            }
            renderQuick(payload.quick_rows || []);
            render(payload.rows || []);
            const checkedAt = payload.checked_at || "";
            const targetText = (Array.isArray(payload.target_hosts) && payload.target_hosts.length)
              ? (" Target: " + payload.target_hosts.join(", "))
              : " Target: none (quick overview only)";
            const modeText = payload.inventory_mode === "quick-only"
              ? " Mode: quick-only"
              : " Mode: deep lookup";
            statusEl.textContent = "Inventory refreshed. Checked at: " + checkedAt + "." + targetText + "." + modeText;
            appendDebug("loadInventory success: mode=" + String(payload.inventory_mode || "") + " quick_rows=" + String((payload.quick_rows || []).length) + " deep_rows=" + String((payload.rows || []).length));
          } catch (err) {
            statusEl.textContent = "Inventory failed: " + ((err && err.message) || "Unknown error.");
            quickResultsEl.innerHTML = "";
            resultsEl.innerHTML = "";
            appendDebug("loadInventory exception: " + ((err && err.message) || String(err)));
          } finally {
            if (progressTimer) clearInterval(progressTimer);
            if (refreshBtn) {
              refreshBtn.disabled = false;
              refreshBtn.textContent = "Refresh Inventory";
            }
          }
        }

        if (deepInventoryFormEl) {
          deepInventoryFormEl.addEventListener("submit", function (evt) {
            evt.preventDefault();
            loadInventory();
          });
        } else if (refreshBtn) {
          refreshBtn.addEventListener("click", function () {
            loadInventory();
          });
        }

        if (debugClearBtn) {
          debugClearBtn.addEventListener("click", function () {
            if (debugLogEl) {
              debugLogEl.value = "";
              appendDebug("debug log cleared");
            }
          });
        }

        if (debugCopyBtn) {
          debugCopyBtn.addEventListener("click", async function () {
            try {
              const text = debugLogEl ? debugLogEl.value : "";
              if (!text) return;
              if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                appendDebug("debug copied to clipboard");
                return;
              }
              if (debugLogEl) {
                debugLogEl.select();
                document.execCommand("copy");
                appendDebug("debug copied to clipboard (execCommand)");
              }
            } catch (err) {
              appendDebug("debug copy failed: " + ((err && err.message) || String(err)));
            }
          });
        }

        window.addEventListener("error", function (evt) {
          appendDebug("window.error: " + (evt && evt.message ? evt.message : "unknown"));
        });

        window.addEventListener("unhandledrejection", function (evt) {
          const reason = evt && evt.reason ? (evt.reason.message || String(evt.reason)) : "unknown";
          appendDebug("unhandledrejection: " + reason);
        });

        if (renewalCreateRunBtn) {
          renewalCreateRunBtn.addEventListener("click", async function () {
            try {
              await createRenewalRun();
            } catch (err) {
              alert((err && err.message) || "Failed to create renewal run.");
            }
          });
        }

        if (renewalPrecheckBtn) {
          renewalPrecheckBtn.addEventListener("click", async function () {
            try { await runRenewalAction("precheck"); } catch (err) { alert((err && err.message) || "Precheck failed."); }
          });
        }
        if (renewalGenerateCsrBtn) {
          renewalGenerateCsrBtn.addEventListener("click", async function () {
            try { await runRenewalAction("generate_csr"); } catch (err) { alert((err && err.message) || "CSR generation failed."); }
          });
        }
        if (renewalDownloadCsrBtn) {
          renewalDownloadCsrBtn.addEventListener("click", function () { downloadCsrBundle(); });
        }
        if (renewalUploadBtn) {
          renewalUploadBtn.addEventListener("click", async function () {
            try { await runRenewalAction("upload_signed_cert"); } catch (err) { alert((err && err.message) || "Upload failed."); }
          });
        }
        if (renewalRestartBtn) {
          renewalRestartBtn.addEventListener("click", async function () {
            try { await runRenewalAction("restart_services"); } catch (err) { alert((err && err.message) || "Restart failed."); }
          });
        }
        if (renewalValidateBtn) {
          renewalValidateBtn.addEventListener("click", async function () {
            try { await runRenewalAction("final_validate"); } catch (err) { alert((err && err.message) || "Validation failed."); }
          });
        }

        appendDebug("page4 script initialized");
        loadInventory();
      })();
    </script>
  </body>
</html>
""".replace("__AUTH_USER__", auth_user).replace("__ENV_TEXT__", escape(env_text)).replace("__ENV_CLASS__", env_css_class).replace("__HAS_CACHED_CUCM_PASS__", "true" if has_cached_cucm_pass else "false").replace("__CREDENTIAL_EXPIRES_AT_MS__", str(credential_expires_at_ms)).replace(
  "__TARGET_OPTIONS__",
  "".join(
    [
      f"<option value=\"{escape(str(item.get('hostname', '') or '').strip().lower())}\">{escape(str(item.get('system', '') or '').strip())} - {escape(str(item.get('role', '') or '').strip())} ({escape(str(item.get('hostname', '') or '').strip().lower())})</option>"
      for item in LAB_CERT_MANAGER_TARGETS
    ]
  ),
)

  return HTMLResponse(
    content=html,
    headers={
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "Pragma": "no-cache",
      "Expires": "0",
    },
  )


@app.get("/cert-manager/lab/inventory")
@app.post("/cert-manager/lab/inventory")
async def cert_manager_lab_inventory(request: Request):
  session, username = _require_admin_session(request)
  cucm_host = str(session.get("cucm_host", "") or "")
  cert_manager_enabled = _feature_enabled(
    CERT_MANAGER_PAGE_ENABLED,
    lab_only=(CERT_MANAGER_PAGE_LAB_ONLY and PREVIEW_FEATURES_LAB_ONLY_DEFAULT),
    cucm_host=cucm_host,
  )
  if not cert_manager_enabled or not _is_lab_environment(cucm_host):
    return JSONResponse(
      {
        "ok": False,
        "detail": "Server Certificate Manager is LAB-only and disabled in this environment.",
      },
      status_code=403,
    )

  target_hosts = []
  platform_user = ""
  platform_pass = ""

  if request.method.upper() == "POST":
    try:
      payload = await request.json()
      if isinstance(payload, dict):
        raw_target_hosts = payload.get("target_hosts", [])
        if isinstance(raw_target_hosts, list):
          target_hosts = [
            str(item or "").strip().lower()
            for item in raw_target_hosts
            if str(item or "").strip()
          ]
        else:
          single_target = str(payload.get("target_host", "") or "").strip().lower()
          if single_target:
            target_hosts = [single_target]
        platform_user = str(payload.get("platform_user", "") or "").strip()
        platform_pass = str(payload.get("platform_pass", "") or "").strip()
    except Exception:
      payload = {}

  for target_host in target_hosts:
    if target_host not in LAB_CERT_MANAGER_ALLOWED_HOSTS:
      return JSONResponse(
        {
          "ok": False,
          "detail": f"Invalid target host: {target_host}",
        },
        status_code=400,
      )

  if platform_user and platform_pass:
    resolved_cucm_user = platform_user
    resolved_cucm_pass = platform_pass
  else:
    _, resolved_cucm_user, resolved_cucm_pass = _resolve_cucm_credentials(request, cucm_host, "", "")

  if not str(resolved_cucm_user or "").strip() or not str(resolved_cucm_pass or "").strip():
    return JSONResponse(
      {
        "ok": False,
        "detail": "Missing platform credentials. Use cached login or provide Platform Username/Password.",
      },
      status_code=400,
    )

  quick_rows = _collect_lab_tls_quick_expiry(target_hosts)
  rows = []
  if target_hosts:
    rows = _collect_lab_certificate_inventory(resolved_cucm_user, resolved_cucm_pass, target_hosts)
  return JSONResponse(
    {
      "ok": True,
      "operator": username,
      "environment": "LAB",
      "target_hosts": target_hosts,
      "inventory_mode": "deep" if target_hosts else "quick-only",
      "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
      "quick_rows": quick_rows,
      "rows": rows,
      "restart_policy": {
        "full_server_restart_allowed": False,
        "service_restart_mode": "separate",
      },
    }
  )


@app.post("/cert-manager/lab/inventory-sync", response_class=HTMLResponse)
async def cert_manager_lab_inventory_sync(request: Request):
  session, username = _require_admin_session(request)
  cucm_host = str(session.get("cucm_host", "") or "")
  cert_manager_enabled = _feature_enabled(
    CERT_MANAGER_PAGE_ENABLED,
    lab_only=(CERT_MANAGER_PAGE_LAB_ONLY and PREVIEW_FEATURES_LAB_ONLY_DEFAULT),
    cucm_host=cucm_host,
  )
  if not cert_manager_enabled or not _is_lab_environment(cucm_host):
    return HTMLResponse("<h3>403 Forbidden</h3><p>Server Certificate Manager is LAB-only and disabled in this environment.</p>", status_code=403)

  form = await request.form()
  target_hosts = []
  for val in form.getlist("target_hosts"):
    text = str(val or "").strip().lower()
    if text:
      target_hosts.append(text)

  _, resolved_user, resolved_pass = _resolve_cucm_credentials(request, cucm_host, "", "")
  if not str(resolved_user or "").strip() or not str(resolved_pass or "").strip():
    return HTMLResponse(
      "<h3>Missing Credentials</h3><p>Cached platform credentials were not found. Re-login and retry Page 4.</p>",
      status_code=400,
    )

  quick_rows = _collect_lab_tls_quick_expiry(target_hosts)
  rows = _collect_lab_certificate_inventory(resolved_user, resolved_pass, target_hosts) if target_hosts else []

  def _cell(v):
    return escape(str(v if v is not None else "-"))

  quick_html_rows = "".join(
    [
      "<tr>"
      f"<td>{_cell(r.get('system', ''))}</td>"
      f"<td>{_cell(r.get('certificate', ''))}</td>"
      f"<td>{_cell(r.get('expiration_date_short', r.get('expiration_date', '')))}</td>"
      f"<td>{_cell(r.get('days_remaining', '-'))}</td>"
      f"<td>{_cell(r.get('status', ''))}</td>"
      "</tr>"
      for r in quick_rows
    ]
  )

  deep_rows = []
  for r in rows:
    days = r.get("days_remaining")
    if isinstance(days, int) and days <= 45:
      deep_rows.append(r)
    elif isinstance(days, float) and days <= 45:
      deep_rows.append(r)
    elif "fetch failed" in str(r.get("status", "")).lower():
      deep_rows.append(r)

  deep_html_rows = "".join(
    [
      "<tr>"
      f"<td>{_cell(r.get('system', ''))}</td>"
      f"<td>{_cell(r.get('certificate', ''))}</td>"
      f"<td>{_cell(r.get('common_name', ''))}</td>"
      f"<td>{_cell(r.get('usage', ''))}</td>"
      f"<td>{_cell(r.get('type', ''))}</td>"
      f"<td>{_cell(r.get('expiration_date', ''))}</td>"
      f"<td>{_cell(r.get('days_remaining', '-'))}</td>"
      f"<td>{_cell(r.get('status', ''))}</td>"
      "</tr>"
      for r in deep_rows
    ]
  )

  checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
  html = f"""
<html>
  <head>
    <title>LAB Inventory (Fallback)</title>
    <style>
      body {{ font-family: Segoe UI, Arial, sans-serif; margin: 14px; background:#f7fbff; color:#12304a; }}
      .card {{ background:#fff; border:1px solid #cfe1f3; border-radius:10px; padding:12px; margin-bottom:10px; }}
      table {{ width:100%; border-collapse:collapse; font-size:13px; }}
      th {{ background:#005eb8; color:#fff; text-align:left; padding:7px; }}
      td {{ border-bottom:1px solid #d5e4f5; padding:7px; vertical-align:top; }}
      .actions a {{ color:#005eb8; font-weight:700; text-decoration:none; }}
    </style>
  </head>
  <body>
    <div class='actions'><a href='/page4'>Back to Page 4</a></div>
    <div class='card'><h3 style='margin:0 0 6px 0;'>LAB Quick Overview</h3><p style='margin:0 0 8px 0;'>Checked at: {escape(checked_at)}</p>
      <table><thead><tr><th>System</th><th>Certificate</th><th>Expiration</th><th>Days Left</th><th>Status</th></tr></thead><tbody>{quick_html_rows or '<tr><td colspan="5">No rows</td></tr>'}</tbody></table>
    </div>
    <div class='card'><h3 style='margin:0 0 6px 0;'>Deep Dive (45 days + failures)</h3>
      <p style='margin:0 0 8px 0;color:#4e6a84;'>Deep lookup runs only when target hosts are selected on Page 4.</p>
      <table><thead><tr><th>System</th><th>Certificate</th><th>Common Name</th><th>Usage</th><th>Type</th><th>Expiration Date</th><th>Days Left</th><th>Status</th></tr></thead><tbody>{deep_html_rows or '<tr><td colspan="8">No rows</td></tr>'}</tbody></table>
    </div>
    <div class='card'><p style='margin:0;'>Operator: {escape(str(username or ''))}</p></div>
  </body>
</html>
"""
  return HTMLResponse(content=html)


@app.post("/cert-manager/lab/renewal/run/create")
async def cert_manager_lab_renewal_create_run(request: Request):
  session, username = _require_admin_session(request)
  cucm_host = str(session.get("cucm_host", "") or "")
  cert_manager_enabled = _feature_enabled(
    CERT_MANAGER_PAGE_ENABLED,
    lab_only=(CERT_MANAGER_PAGE_LAB_ONLY and PREVIEW_FEATURES_LAB_ONLY_DEFAULT),
    cucm_host=cucm_host,
  )
  if not cert_manager_enabled or not _is_lab_environment(cucm_host):
    return JSONResponse({"ok": False, "detail": "Server Certificate Manager is LAB-only and disabled in this environment."}, status_code=403)

  payload = await request.json()
  target_hosts = []
  if isinstance(payload, dict):
    raw = payload.get("target_hosts", [])
    if isinstance(raw, list):
      target_hosts = [str(item or "").strip().lower() for item in raw if str(item or "").strip()]

  if len(target_hosts) != 2:
    return JSONResponse({"ok": False, "detail": "Select exactly 2 target hosts to create a renewal run."}, status_code=400)

  for host in target_hosts:
    if host not in LAB_CERT_MANAGER_ALLOWED_HOSTS:
      return JSONResponse({"ok": False, "detail": f"Invalid target host: {host}"}, status_code=400)

  with CERT_RENEWAL_RUNS_LOCK:
    run = _create_cert_renewal_run(username, target_hosts)
    CERT_RENEWAL_RUNS[run["run_id"]] = run
    _prune_cert_renewal_runs_locked()
    snapshot = _snapshot_cert_renewal_run(run)

  return JSONResponse({"ok": True, "run": snapshot})


@app.get("/cert-manager/lab/renewal/run/{run_id}")
def cert_manager_lab_renewal_get_run(request: Request, run_id: str):
  _session, _username = _require_admin_session(request)
  with CERT_RENEWAL_RUNS_LOCK:
    run = CERT_RENEWAL_RUNS.get(run_id)
    if not run:
      return JSONResponse({"ok": False, "detail": "Renewal run not found."}, status_code=404)
    snapshot = _snapshot_cert_renewal_run(run)
  return JSONResponse({"ok": True, "run": snapshot})


@app.post("/cert-manager/lab/renewal/run/{run_id}/action")
async def cert_manager_lab_renewal_run_action(request: Request, run_id: str):
  session, _username = _require_admin_session(request)
  cucm_host = str(session.get("cucm_host", "") or "")
  cert_manager_enabled = _feature_enabled(
    CERT_MANAGER_PAGE_ENABLED,
    lab_only=(CERT_MANAGER_PAGE_LAB_ONLY and PREVIEW_FEATURES_LAB_ONLY_DEFAULT),
    cucm_host=cucm_host,
  )
  if not cert_manager_enabled or not _is_lab_environment(cucm_host):
    return JSONResponse({"ok": False, "detail": "Server Certificate Manager is LAB-only and disabled in this environment."}, status_code=403)

  payload = await request.json()
  if not isinstance(payload, dict):
    payload = {}

  action = str(payload.get("action", "") or "").strip().lower()
  cert_alias = str(payload.get("cert_alias", "tomcat") or "tomcat").strip() or "tomcat"
  signed_chain_pem = str(payload.get("signed_chain_pem", "") or "")
  platform_user = str(payload.get("platform_user", "") or "").strip()
  platform_pass = str(payload.get("platform_pass", "") or "").strip()

  if platform_user and platform_pass:
    resolved_user = platform_user
    resolved_pass = platform_pass
  else:
    _, resolved_user, resolved_pass = _resolve_cucm_credentials(request, cucm_host, "", "")

  if not str(resolved_user or "").strip() or not str(resolved_pass or "").strip():
    return JSONResponse({"ok": False, "detail": "Missing platform credentials. Use cached login or provide Platform Username/Password."}, status_code=400)

  with CERT_RENEWAL_RUNS_LOCK:
    run = CERT_RENEWAL_RUNS.get(run_id)
    if not run:
      return JSONResponse({"ok": False, "detail": "Renewal run not found."}, status_code=404)

    hosts = list(run.get("target_hosts", []) or [])
    for host in hosts:
      if action == "precheck":
        ok, detail = _renewal_precheck_host(host, resolved_user, resolved_pass)
        _set_cert_run_step_status(run, host, "precheck", "ok" if ok else "failed", detail)
      elif action == "generate_csr":
        ok, detail, csr_text = _renewal_generate_csr_host(host, resolved_user, resolved_pass, cert_alias)
        if ok and csr_text:
          run.setdefault("hosts", {}).setdefault(host, {})["csr_pem"] = csr_text
        _set_cert_run_step_status(run, host, "generate_csr", "ok" if ok else "failed", detail)
      elif action == "upload_signed_cert":
        if not signed_chain_pem.strip():
          _set_cert_run_step_status(run, host, "upload_signed_cert", "failed", "Signed chain PEM is required for upload.")
          continue
        ok, detail = _renewal_upload_signed_chain_host(host, resolved_user, resolved_pass, signed_chain_pem)
        _set_cert_run_step_status(run, host, "upload_signed_cert", "ok" if ok else "failed", detail)
      elif action == "restart_services":
        ok, detail = _renewal_restart_services_host(host, resolved_user, resolved_pass)
        _set_cert_run_step_status(run, host, "restart_services", "ok" if ok else "warning", detail)
      elif action == "final_validate":
        ok, detail = _renewal_final_validate_host(host, resolved_user, resolved_pass, cert_alias)
        _set_cert_run_step_status(run, host, "final_validate", "ok" if ok else "failed", detail)
      else:
        return JSONResponse({"ok": False, "detail": f"Unsupported action: {action}"}, status_code=400)

    snapshot = _snapshot_cert_renewal_run(run)

  return JSONResponse({"ok": True, "run": snapshot})


@app.get("/menu-admin", response_class=HTMLResponse)
@app.get("/menu2", response_class=HTMLResponse)
@app.get("/page2", response_class=HTMLResponse)
def menu_admin_page(request: Request):
  session = _get_auth_session(request) or {}
  now_epoch = time.time()
  session_username = str(session.get("username", ""))
  if not _is_admin_user(session_username):
    return HTMLResponse(
      content="<h3>403 Forbidden</h3><p>You are not authorized to access Administrative Items.</p>",
      status_code=403,
    )

  auth_user = escape(session_username)
  auth_cucm_host = str(session.get("cucm_host", ""))
  has_cached_cucm_pass = _has_valid_cached_secret(session, "cucm_pass", now_epoch)
  if not has_cached_cucm_pass:
    _page2_sid = request.cookies.get(SESSION_COOKIE_NAME, "")
    if _page2_sid:
      has_cached_cucm_pass = bool((AUTH_SESSION_SECRETS.get(_page2_sid, {}).get("cucm_pass", "") or "").strip())
  credential_expires_at = float(session.get("credential_expires_at", 0) or 0)
  credential_expires_at_ms = int(credential_expires_at * 1000) if (has_cached_cucm_pass and credential_expires_at > 0) else 0
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
        padding: 10px 16px;
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

      .topbar-brand {
        display: flex;
        align-items: center;
        gap: 10px;
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

      .topbar-status {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: center;
      }

      .topbar-status > * {
        display: inline-flex;
        align-items: center;
        min-height: 32px;
        padding: 6px 10px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.35);
        box-sizing: border-box;
        font-size: 11px;
        font-weight: 700;
        line-height: 1.1;
      }

      .topbar-auth-pill {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
      }

      .topbar-status .env-banner {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
        box-shadow: none;
      }

      .topbar-status .session-timer {
        background: linear-gradient(180deg, #fff4df, #ffdca3);
        color: #6a3c00;
        border-color: #f0b44a;
        box-shadow: 0 6px 12px rgba(198, 138, 18, 0.22);
      }

      .topbar-status .env-banner.env-banner-prod,
      .topbar-status .env-banner.env-banner-lab {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
        border-color: rgba(255, 255, 255, 0.35);
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
        margin: 8px 0 0 0;
        padding: 10px 16px;
        border-radius: 10px;
        font-weight: 800;
        letter-spacing: 0.2px;
        box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.3);
      }

      .hero-status-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 8px;
      }

      .hero-status-row .env-banner {
        margin: 0;
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

      .session-timer {
        display: none;
        align-items: center;
        gap: 8px;
        padding: 9px 12px;
        margin: 0;
        border-radius: 12px;
        border: 1px solid #f0b44a;
        background: linear-gradient(180deg, #fff4df, #ffe4b8);
        color: #6a3c00;
        box-shadow: 0 10px 18px rgba(198, 138, 18, 0.2);
      }

      .session-timer .timer-label {
        font-weight: 700;
      }

      .session-timer .timer-value {
        font-family: Consolas, monospace;
        font-weight: 700;
      }

      .portal-shell {
        display: grid;
        grid-template-columns: 240px minmax(0, 1fr);
        gap: 14px;
        align-items: start;
      }

      .portal-sidebar {
        position: sticky;
        top: 10px;
        background: linear-gradient(180deg, rgba(0, 47, 108, 0.97), rgba(7, 75, 138, 0.96));
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 12px;
        box-shadow: 0 18px 36px rgba(0, 47, 108, 0.18);
        padding: 10px;
      }

      .portal-sidebar h4 {
        margin: 4px 6px 8px 6px;
        color: #fff;
        font-size: 13px;
        letter-spacing: 0.3px;
      }

      .portal-nav {
        display: grid;
        gap: 8px;
      }

      .portal-nav-btn {
        text-align: left;
        width: 100%;
        border-radius: 8px;
        border: 1px solid rgba(255, 255, 255, 0.12);
        background: rgba(255, 255, 255, 0.09);
        color: rgba(255, 255, 255, 0.94);
        padding: 7px 9px;
        font-size: 12px;
        line-height: 1.25;
        font-weight: 600;
        cursor: pointer;
        box-shadow: none;
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

      .portal-nav-btn.start-here-btn {
        background: linear-gradient(180deg, #fff7d8, #ffe8a3);
        border-color: #d7ac2a;
        color: #4f3900;
        box-shadow: 0 10px 18px rgba(198, 138, 18, 0.22);
        line-height: 1.3;
      }

      .portal-nav-btn.start-here-btn:hover,
      .portal-nav-btn.start-here-btn.active {
        background: linear-gradient(180deg, #ffefbb, #ffd978);
        border-color: #bd8e13;
        color: #3f2a00;
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

      .panel {
        background: rgba(255, 255, 255, 0.93);
        border: 1px solid var(--amn-panel-border);
        border-radius: 12px;
        padding: 12px;
        box-shadow: var(--amn-shadow);
        backdrop-filter: blur(6px);
        margin: 0 0 12px 0;
      }

      h3 {
        margin: 4px 0 8px 0;
        color: var(--amn-navy);
        font-size: 17px;
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

      .search-filter-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-bottom: 14px;
      }

      .search-filter-row input {
        flex: 0 0 auto;
        width: 180px;
        padding: 8px 10px;
      }

      .search-filter-row button {
        flex: 0 0 auto;
        padding: 8px 20px;
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
          padding: 8px 10px;
        }

        .compact-inline-row span {
          width: auto;
        }

        .page-hero {
          padding: 10px 8px;
        }

        .page-title {
          font-size: 18px;
        }

        .portal-shell {
          grid-template-columns: 1fr;
        }

        .portal-sidebar {
          position: static;
        }

        .portal-nav {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
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
      <div class="topbar-status">
        <span class="topbar-auth-pill">Authenticated Operator: __AUTH_USER__</span>
        <div class="env-banner __ENV_CLASS__">__ENV_TEXT__</div>
        <div id="session-timer-banner" class="session-timer" aria-live="polite">
          <span class="timer-label">Auto logout in:</span>
          <span id="session-timer-remaining" class="timer-value"></span>
        </div>
      </div>
      <div class="topbar-actions">
        <a class="topbar-btn topbar-btn-login" href="/">Log In</a>
        <a class="topbar-btn topbar-btn-logout" href="/logout">Log Out</a>
      </div>
    </header>

    <main class="content">
      <section class="page-hero">
        <span class="page-kicker">Administrative Workbench</span>
        <div class="page-title-row">
          <div class="page-title-block">
            <h2 class="page-title">Administrative Items</h2>
            <p class="page-subtitle">Bulk operations, strike workflows, export utilities, and translation lookups in a single workspace for higher-volume admin work.</p>
          </div>
          <div class="page-meta-card">
            <span class="page-meta-label">Portal Version</span>
            <span class="page-meta-value">v1.0 Current</span>
            <p class="page-meta-note">v1.01 queued for VeraSMART automation enhancement.</p>
          </div>
        </div>
        <div class="hero-link-grid">
          <a class="hero-link-card" href="/menu">
            <strong>Main Operations</strong>
            <span>Return to standard user-facing voice operations workflows.</span>
          </a>
          <a class="hero-link-card" href="/audit-trail">
            <strong>Action History</strong>
            <span>Review recent portal actions and download the audit CSV.</span>
          </a>
          <a class="hero-link-card" href="/page3?panel=sms-number-look">
            <strong>📞 SMS Item Menu</strong>
            <span>Manage Twilio number verification and lookup operations.</span>
          </a>
          <a class="hero-link-card" href="/page4">
            <strong>🔐 Server Certificate Manager</strong>
            <span>LAB-only read-only certificate inventory for CUCM, IM and Presence, and Unity.</span>
          </a>
        </div>
      </section>

      <div class="portal-shell">
        <aside class="portal-sidebar">
          <h4>Administrative Menu</h4>
          <div class="portal-nav">
            <button type="button" class="portal-nav-btn start-here-btn active" data-panel="personlookup">Start Here!<br>Employee Lookup By Name</button>
            <button type="button" class="portal-nav-btn" data-panel="strike">Strike Mode - Add iPhone and Android</button>
            <button type="button" class="portal-nav-btn" data-panel="mobiledelete">Remove only Jabber Mobile</button>
            <button type="button" class="portal-nav-btn" data-panel="rpo">Extract RPO Phones</button>
            <button type="button" class="portal-nav-btn" data-panel="adddn">Add Directory Numbers (CSV)</button>
            <button type="button" class="portal-nav-btn" data-panel="exportdn">Export Directory Numbers</button>
            <button type="button" class="portal-nav-btn" data-panel="exportusers">Export End Users</button>
            <button type="button" class="portal-nav-btn" data-panel="translookup">Translation Pattern Lookup</button>
            <button type="button" class="portal-nav-btn" data-panel="transtemplate">Translation Pattern Template</button>
            <button type="button" class="portal-nav-btn" data-panel="strikemask-template">Add Translation for Strike Mask Use (CSV Template)</button>
            <button type="button" class="portal-nav-btn" data-panel="verasmart-lab">VeraSMART Automation (v1.01 LAB)</button>
            <button type="button" class="portal-nav-btn" data-panel="strikemask">Strike Mask - Masked Calling</button>
            <button type="button" class="portal-nav-btn" onclick="window.location.href='/menu?panel=teams-telephony'">Create Teams Telephony User (Main Ops)</button>
            <button type="button" class="portal-nav-btn portal-nav-btn-danger" onclick="window.location.href='/menu?panel=teams-telephony-remove'">Remove Teams Telephony User (Main Ops)</button>
            <button type="button" class="portal-nav-btn portal-nav-btn-danger" onclick="window.location.href='/menu?panel=offboard'">Separate Employeed-Delete Jabber/VM (Main Ops)</button>
            <button type="button" class="portal-nav-btn" onclick="window.location.href='/menu?panel=linegroup'">Update Hunt List Line Group (Main Ops)</button>
            <button type="button" class="portal-nav-btn" data-panel="jabbernotify">Send Jabber Number/Training Notification</button>
            <button type="button" class="portal-nav-btn" data-panel="bulkperson">Bulk Person Lookup (CSV)</button>
            <button type="button" class="portal-nav-btn" data-panel="bulkextension">Bulk Extension Lookup (CSV)</button>
            <button type="button" class="portal-nav-btn" onclick="window.location.href='/page3?panel=sms-number-look'">📞 SMS Item Menu (Page 3)</button>
            <button type="button" class="portal-nav-btn portal-nav-btn-info" style="background:#2563eb;border-color:#2563eb;" onclick="window.location.href='/settings'">⚙️ DN Prefix Settings</button>
            <button type="button" class="portal-nav-btn" data-panel="ldapsync">Trigger CUCM LDAP Sync</button>
            <button type="button" class="portal-nav-btn" data-panel="unityldapsync">Trigger Unity LDAP Sync</button>
            <button type="button" class="portal-nav-btn" data-panel="sep-sms-report">📧 SMS Separation Email Process</button>
            <button type="button" class="portal-nav-btn" data-panel="dn-avail-report">📊 DN Number Pool Availability Report</button>
            <button type="button" class="portal-nav-btn" onclick="window.location.href='/page4'">🔐 Server Certificate Manager (Page 4)</button>
          </div>
        </aside>

        <section class="portal-main">

      <section class="panel tool-panel active" data-panel="personlookup">
        <h3>Employee Lookup by Name</h3>
        <p>Search by last name (optional first name), then use the result to prefill Strike Mode.</p>
        <form id="admin-person-lookup-form">
          <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">
          <input type="hidden" name="include_teams_status" value="1">
          <div class="search-filter-row">
            <input name="last_name" placeholder="Last Name *" required>
            <input name="first_name" placeholder="First Name (optional)">
            <button type="submit">Search</button>
          </div>
        </form>

        <p id="admin-person-lookup-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
        <div id="admin-person-lookup-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="strike">
        <h3>Strike Mode - Add in both Jabber iPhone and Android (Option 5)</h3>
        <form id="admin-strike-form" action="/add/secondary-strike-devices" method="post">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          User ID for person to add STRIKE MODE devices for:<br>
          <input id="admin-strike-target-user" name="target_user" placeholder="john.doe" required><br><br>

          <button type="submit">Run STRIKE MODE</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="mobiledelete">
        <h3>Remove only Jabber Mobile - iPhone or Android</h3>
        <p>Lookup by last name, then remove Jabber iPhone (TCT), Jabber Android (BOT), or both. This does not delete CSF or voicemail.</p>
        <form id="admin-mobile-delete-lookup-form">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          <div class="compact-inline-row">
            <span>Last Name:</span>
            <input name="last_name" placeholder="Smith" required>
          </div><br>

          <div class="compact-inline-row">
            <span>First Name (optional):</span>
            <input name="first_name" placeholder="John">
          </div><br>

          <button type="submit">Search Users for Mobile Delete</button>
        </form>

        <p id="admin-mobile-delete-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
        <div id="admin-mobile-delete-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="rpo">
        <h3>Extract RPO Phones (Option 18)</h3>
        <form action="/export/rpo-phones" method="post">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          User IDs (one per line):<br>
          <textarea name="rpo_userids" rows="8" placeholder="john.doe&#10;jane.smith" required></textarea><br><br>

          <button type="submit">Run Extract RPO Phones</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="adddn">
        <h3>Add Directory Numbers (Upload CSV)</h3>
        <form action="/add/directorynumbers" method="post" enctype="multipart/form-data">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          CSV File:<br>
          <input type="file" name="csv_file" required><br><br>

          <a href="/download/add-directorynumbers-template">Download CSV Template</a><br><br>

          <button type="submit">Run Add Directory Numbers</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="exportdn">
        <h3>Export Directory Numbers</h3>
        <form action="/export/directorynumbers" method="post">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

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
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          Last Name:<br>
          <input name="lastname" required><br><br>

          <button type="submit">Export End Users</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="ldapsync">
        <h3>Trigger CUCM LDAP Sync</h3>
        <p>Triggers CUCM LDAP sync for the active environment automatically. PROD uses LDAP_AMN and LAB uses LAB_LDAP_AMN.</p>
        <form action="/admin/ldap-sync" method="post">
          <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          <button type="submit">Run CUCM LDAP Sync</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="unityldapsync">
        <h3>Trigger Unity LDAP Sync</h3>
        <p>Triggers Unity LDAP import sync for the active environment automatically (LAB or PROD based on your current session host).</p>
        <form action="/admin/unity-ldap-sync" method="post">
          <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">
          <input type="hidden" name="unity_user" value="">
          <input type="hidden" name="unity_pass" value="">

          <button type="submit">Run Unity LDAP Sync</button>
        </form>
      </section>

      <section class="panel tool-panel" data-panel="translookup">
        <h3>Translation Pattern Lookup</h3>
        <p>Search translation patterns and return pattern, description, and called party transform mask.</p>
        <form id="admin-trans-pattern-form">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

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
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          Example starts with:<br>
          <input name="pattern_prefix" value="3148984689" required><br><br>

          <button type="submit">Build Example Template</button>
        </form>

        <p id="admin-trans-template-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Click Build Example Template to load the example.</p>
        <p id="admin-trans-template-summary" style="color:#355978; min-height:18px;"></p>
        <p><a id="admin-trans-template-download" href="#" style="display:none; font-weight:700;">Download CSV Output</a></p>
        <textarea id="admin-trans-template-preview" rows="8" readonly style="width:100%;"></textarea>
      </section>

      <section class="panel tool-panel" data-panel="strikemask-template">
        <h3>Add Translation for Strike Mask Use (CSV Template)</h3>
        <p>Download a ready-to-fill CSV template for pre-staging Strike Mask translation patterns in bulk. This template is not tied to 945 only; you can use any numbering range.</p>
        <p style="margin-top:8px; color:#355978;"><strong>Fixed constants applied for every row:</strong> route partition <strong>ENT_DEVICE_PT</strong> and called party transform mask <strong>2481001</strong>.</p>
        
        <p><a href="/download/strike-mask-translation-template" style="font-weight:700;">Download Strike Mask Translation Upload Template</a></p>
        
        <p style="margin-top:10px; color:#355978;">Template notes:</p>
        <ul style="margin-top:6px; color:#355978;">
          <li><strong>pattern</strong>: the Strike Mask translation pattern number to create.</li>
          <li><strong>description</strong>: use a standard available marker like <em>Strike Mask - &lt;pattern&gt; Available</em>.</li>
          <li><strong>notes</strong>: optional internal tracking note.</li>
        </ul>
        
        <hr style="margin:16px 0; border:none; border-top:1px solid #ddd;">
        <h4 style="margin-top:16px; color:#002f6c;">Upload CSV to Create Patterns</h4>
        <form id="strikemask-upload-form" method="post" action="/strike-mask-translation/upload" enctype="multipart/form-data">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">
          <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
          
          CSV File:<br>
          <input type="file" name="csv_file" accept=".csv" required><br><br>
          CUCM Password (only if prompted / session expired):<br>
          <input type="password" name="cucm_pass" placeholder="Optional - enter only if needed"><br><br>
          <button type="submit">Create Translation Patterns</button>
        </form>
        
        <p id="strikemask-upload-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Upload a CSV and click Create Translation Patterns. Detailed errors will appear here.</p>
        <div id="strikemask-upload-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="verasmart-lab">
        <h3>VeraSMART Automation (v1.01 LAB-Only Scaffold)</h3>
        <p>This is a lab scaffold only. Upload a queue CSV, review run status, and validate intake/audit flow. No VeraSMART write action executes yet.</p>
        <p><a href="/download/verasmart-queue-template" style="font-weight:700;">Download Queue CSV Template</a></p>
        <form id="verasmart-lab-queue-form" enctype="multipart/form-data">
          CSV File:<br>
          <input type="file" name="csv_file" accept=".csv" required><br><br>
          <button type="submit">Upload Queue (LAB)</button>
          <button type="button" id="verasmart-lab-refresh" style="margin-left:8px;">Refresh Run Status</button>
        </form>
        <p id="verasmart-lab-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Upload a queue CSV to create a LAB run.</p>
        <div id="verasmart-lab-runs" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="strikemask">
        <h3>Strike Mask - Masked Calling (Page 2)</h3>
        <p>Apply or reverse Strike Mask for masked calling. Strike Mask uses a 945-series translation pattern to mask the caller's Jabber extension when making calls.</p>
        
        <h4 style="margin-top:18px;">Lookup Strike Mask Status</h4>
        <p>Search by last name to see if the user has active Strike Mask operations or available patterns to apply.</p>
        <form id="admin-strikemask-lookup-form">
          <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">
          <div class="search-filter-row">
            <input name="last_name" placeholder="Last Name *" required>
            <input name="first_name" placeholder="First Name (optional)">
            <button type="submit">Search</button>
          </div>
        </form>
        
        <p id="admin-strikemask-lookup-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter a last name and click Search.</p>
        <div id="admin-strikemask-lookup-results" style="overflow-x:auto;"></div>

        <div style="margin-top:14px;">
          <button type="button" id="admin-strikemask-list-inuse" class="mini-btn">List All Currently In-Use Strike Masks</button>
          <p id="admin-strikemask-inuse-status" style="color:#2c5c8a; min-height:18px; margin-top:10px;">Click the button to load in-use patterns.</p>
          <div id="admin-strikemask-inuse-results" style="overflow-x:auto;"></div>
        </div>
        
        <hr style="margin:20px 0; border:none; border-top:1px solid #d0dce8;">
        
        <h4>Reverse Strike Mask</h4>
        <p>Enter an operation ID to restore the translation pattern to "Available" state and remove Strike Mask from Jabber devices.</p>
        <form id="admin-strikemask-reverse-form">
          <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">
          <div class="compact-inline-row">
            <span>Operation ID:</span>
            <input name="operation_id" placeholder="12345678-abcd-1234-5678-abcdef123456" required>
          </div><br>
          <button type="submit">Reverse Strike Mask</button>
        </form>
        
        <p id="admin-strikemask-reverse-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Enter an operation ID and click Reverse.</p>
        <p id="admin-strikemask-reverse-summary" style="color:#355978; min-height:18px;"></p>
      </section>

      <section class="panel tool-panel" data-panel="jabbernotify">
        <h3>Send Jabber Training Notification</h3>
        <p>Search for an employee by last name, then send them the Cisco Jabber ready email (with their telephone number and training link). Use this to test or resend the notification.</p>
        <form id="jabbernotify-form">
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">
          <div class="compact-inline-row">
            <span>Last Name:</span>
            <input id="jabbernotify-last-name" placeholder="Smith" required>
          </div><br>
          <div class="compact-inline-row">
            <span>First Name (optional):</span>
            <input id="jabbernotify-first-name" placeholder="John">
          </div><br>
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
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

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
          <input type="hidden" name="cucm_user" value="__AUTH_USER__">
          <input type="hidden" name="cucm_pass" value="">

          CSV File:<br>
          <input type="file" name="csv_file" accept=".csv" required><br><br>

          <button type="submit">Run Bulk Extension Lookup</button>
        </form>
        <p id="admin-bulk-extension-status" style="color:#2c5c8a; min-height:18px; margin-top:12px;">Upload a CSV to run bulk lookup.</p>
        <p id="admin-bulk-extension-summary" style="color:#355978; min-height:18px;"></p>
        <p><a id="admin-bulk-extension-download" href="#" style="display:none; font-weight:700;">Download CSV Output</a></p>
        <textarea id="admin-bulk-extension-preview" rows="10" readonly style="width:100%;"></textarea>
      </section>

      <section class="panel tool-panel" data-panel="sep-sms-report">
        <h3>SMS Separation Email Process</h3>
        <p>Automatically emails a report of SMS numbers belonging to offboarded employees so they can be manually removed from Twilio or Aerialink. The scheduler runs at the configured time each day (or week).</p>

        <div style="background:#f0f4fa;border:1px solid #c5d4e8;border-radius:6px;padding:18px;margin-bottom:20px;">
          <h4 style="margin:0 0 14px 0;color:#002f6c;">Scheduler Settings</h4>
          <div id="sep-sms-config-loading" style="color:#888;font-size:13px;">Loading settings…</div>
          <div id="sep-sms-config-form-wrap" style="display:none">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px 20px;margin-bottom:14px;">
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Primary Recipient *</label>
                <input id="sep-cfg-recipient" type="email" placeholder="Laura.Alvarez@amnhealthcare.com" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Second Recipient <span style="font-weight:400;color:#888">(optional)</span></label>
                <input id="sep-cfg-recipient-2" type="email" placeholder="Leave blank to disable" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">From Address</label>
                <input id="sep-cfg-from" type="email" placeholder="noreply@amnhealthcare.com" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Enabled</label>
                <select id="sep-cfg-enabled" style="width:100%;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <option value="true">✅ Yes — scheduler active</option>
                  <option value="false">❌ No — paused</option>
                </select>
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Send Time (PST/PDT)</label>
                <div style="display:flex;gap:8px;align-items:center">
                  <input id="sep-cfg-hour" type="number" min="0" max="23" placeholder="8" style="width:70px;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <span style="color:#555">:</span>
                  <input id="sep-cfg-minute" type="number" min="0" max="59" placeholder="0" style="width:70px;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <span style="font-size:12px;color:#888">24-hr PST/PDT</span>
                </div>
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Frequency</label>
                <select id="sep-cfg-frequency" style="width:100%;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <option value="daily">Daily (previous day window)</option>
                  <option value="weekly">Weekly (previous Mon–Sun window)</option>
                </select>
              </div>
              <div id="sep-cfg-weekly-day-row">
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Weekly Fire Day</label>
                <select id="sep-cfg-weekly-day" style="width:100%;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <option value="monday">Monday</option>
                  <option value="tuesday">Tuesday</option>
                  <option value="wednesday">Wednesday</option>
                  <option value="thursday">Thursday</option>
                  <option value="friday">Friday</option>
                  <option value="saturday">Saturday</option>
                  <option value="sunday">Sunday</option>
                </select>
              </div>
            </div>
            <button type="button" id="sep-sms-save-btn" style="background:#1565c0;color:#fff;border:none;padding:9px 22px;border-radius:6px;font-size:13px;cursor:pointer;font-weight:600;">💾 Save Settings</button>
            <span id="sep-sms-save-status" style="margin-left:12px;font-size:13px;"></span>
          </div>
        </div>

        <div style="margin-bottom:20px;">
          <button type="button" id="sep-sms-run-btn" style="background:#1a237e;color:#fff;border:none;padding:10px 24px;border-radius:6px;font-size:14px;cursor:pointer;font-weight:600;">▶ Run Report Now</button>
          <span style="font-size:12px;color:#888;margin-left:12px;">Runs the report for the previous day immediately and sends the email.</span>
        </div>
        <div id="sep-sms-run-status" style="min-height:18px;margin-bottom:16px;"></div>

        <h4 style="color:#002f6c;margin-bottom:8px;">Recent Send History</h4>
        <button type="button" id="sep-sms-history-btn" style="font-size:12px;padding:5px 14px;margin-bottom:10px;">Refresh History</button>
        <div id="sep-sms-history-loading" style="color:#888;font-size:13px;display:none;">Loading…</div>
        <div id="sep-sms-history-results" style="overflow-x:auto;"></div>
      </section>

      <section class="panel tool-panel" data-panel="dn-avail-report">
        <h3>DN Number Pool Availability Report</h3>
        <p>Runs a daily check of how many Directory Numbers (DNs) are available for each type (General FTE, Recruiter, Strike) and emails a report. Use this to know when to order more numbers.</p>

        <div style="background:#f0f4fa;border:1px solid #c5d4e8;border-radius:6px;padding:18px;margin-bottom:20px;">
          <h4 style="margin:0 0 14px 0;color:#002f6c;">Scheduler Settings</h4>
          <div id="dn-report-config-loading" style="color:#888;font-size:13px;">Loading settings…</div>
          <div id="dn-report-config-form-wrap" style="display:none">
            <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:10px 14px;margin-bottom:14px;font-size:13px;color:#664d03;">
              ⚠️ CUCM credentials entered here are stored in <strong>settings.json</strong> on the server (plain text).
              Use a read-only AXL service account if possible.
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px 20px;margin-bottom:14px;">
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Primary Recipient *</label>
                <input id="dn-cfg-recipient" type="email" placeholder="admin@amnhealthcare.com" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Second Recipient <span style="font-weight:400;color:#888">(optional)</span></label>
                <input id="dn-cfg-recipient-2" type="email" placeholder="Leave blank to disable" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">From Address</label>
                <input id="dn-cfg-from" type="email" placeholder="noreply@amnhealthcare.com" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Enabled</label>
                <select id="dn-cfg-enabled" style="width:100%;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <option value="true">✅ Yes — scheduler active</option>
                  <option value="false">❌ No — paused</option>
                </select>
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Send Time (PST/PDT)</label>
                <div style="display:flex;gap:8px;align-items:center">
                  <input id="dn-cfg-hour" type="number" min="0" max="23" placeholder="8" style="width:70px;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <span style="color:#555">:</span>
                  <input id="dn-cfg-minute" type="number" min="0" max="59" placeholder="0" style="width:70px;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <span style="font-size:12px;color:#888">24-hr PST/PDT</span>
                </div>
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Low Threshold <span style="font-weight:400;color:#888">(warn if available &lt; this)</span></label>
                <input id="dn-cfg-threshold" type="number" min="1" max="999" placeholder="10" style="width:100px;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">CUCM Host</label>
                <input id="dn-cfg-cucm-host" type="text" placeholder="lascucmpp01.ahs.int" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">CUCM Username</label>
                <input id="dn-cfg-cucm-user" type="text" placeholder="axl-service-account" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">CUCM Password</label>
                <input id="dn-cfg-cucm-pass" type="password" placeholder="••••••••" style="width:100%;box-sizing:border-box;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:600;color:#002f6c;display:block;margin-bottom:4px">Frequency</label>
                <select id="dn-cfg-frequency" style="width:100%;padding:7px 10px;border:1px solid #bcd;border-radius:4px;font-size:13px">
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly (Mondays)</option>
                </select>
              </div>
            </div>
            <button type="button" id="dn-report-save-btn" style="background:#1565c0;color:#fff;border:none;padding:9px 22px;border-radius:6px;font-size:13px;cursor:pointer;font-weight:600;">💾 Save Settings</button>
            <span id="dn-report-save-status" style="margin-left:12px;font-size:13px;"></span>
          </div>
        </div>

        <div style="margin-bottom:20px;">
          <button type="button" id="dn-report-run-btn" style="background:#1a237e;color:#fff;border:none;padding:10px 24px;border-radius:6px;font-size:14px;cursor:pointer;font-weight:600;">▶ Run Report Now</button>
          <span style="font-size:12px;color:#888;margin-left:12px;">Queries CUCM and emails results immediately.</span>
        </div>
        <div id="dn-report-run-status" style="min-height:18px;margin-bottom:16px;"></div>
        <div id="dn-report-run-preview" style="overflow-x:auto;margin-bottom:16px;"></div>

        <h4 style="color:#002f6c;margin-bottom:8px;">Recent Send History</h4>
        <button type="button" id="dn-report-history-btn" style="font-size:12px;padding:5px 14px;margin-bottom:10px;">Refresh History</button>
        <div id="dn-report-history-loading" style="color:#888;font-size:13px;display:none;">Loading…</div>
        <div id="dn-report-history-results" style="overflow-x:auto;"></div>
      </section>

      <script>
        (function () {
          const hasCachedCucmPassword = __HAS_CACHED_CUCM_PASS__;
          const credentialExpiresAtMs = __CREDENTIAL_EXPIRES_AT_MS__;
          const sessionTimerBanner = document.getElementById("session-timer-banner");
          const sessionTimerRemaining = document.getElementById("session-timer-remaining");

          function formatTimerValue(totalSeconds) {
            const safe = Math.max(0, Math.floor(totalSeconds));
            const hours = Math.floor(safe / 3600);
            const minutes = Math.floor((safe % 3600) / 60);
            const seconds = safe % 60;
            return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
          }

          function startCredentialTimer() {
            if (!hasCachedCucmPassword || !sessionTimerBanner || !sessionTimerRemaining || !credentialExpiresAtMs) {
              return;
            }

            sessionTimerBanner.style.display = "flex";

            const updateTimer = () => {
              const remainingMs = credentialExpiresAtMs - Date.now();
              if (remainingMs <= 0) {
                sessionTimerRemaining.textContent = "Expired";
                window.location.href = "/logout";
                return;
              }
              sessionTimerRemaining.textContent = formatTimerValue(remainingMs / 1000);
            };

            updateTimer();
            window.setInterval(updateTimer, 1000);
          }

          startCredentialTimer();

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

              const lastNameEl = document.getElementById("jabbernotify-last-name");
              const firstNameEl = document.getElementById("jabbernotify-first-name");

              const lastName = ((lastNameEl && lastNameEl.value) || "").trim();
              const firstName = ((firstNameEl && firstNameEl.value) || "").trim();
              const cucmUser = "__AUTH_USER__";
              const cucmPass = "";

              if (!lastName) {
                jabberNotifyStatus.textContent = "Last Name is required.";
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

                jabberNotifyStatus.textContent = "Found " + results.length + " user(s). Click Send New Jabber Email to email a user.";

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
                  html += '<td style="padding:7px 10px;"><button type="button" data-notify-uid="' + uid + '" data-notify-tel="' + (r.telephone || "") + '" style="background:#237741;color:#fff;border:none;border-radius:6px;padding:6px 12px;font-weight:700;cursor:pointer;">Send New Jabber Email</button></td>';
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
              const panelKey = (btn.dataset.panel || "").trim();
              if (!panelKey) {
                return;
              }
              showPanel(panelKey);
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
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Teams Telephony</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Jabber Devices</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Actions</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                const ext = r.primary_extension || "\u2014";
                const email = r.email || "\u2014";
                const telephone = r.telephone || "\u2014";
                const uid = r.userid || "";
                const teams = r.teams_telephony || {};
                const teamsIsUser = !!teams.is_teams_user;
                const teamsState = teams.status || (teamsIsUser ? "Yes" : "Not Found");
                const teamsExt = teams.extension || "";
                const teamsText = teamsIsUser
                  ? (teamsExt ? `Yes (${teamsExt})` : "Yes")
                  : (teamsState === "Unknown" ? "Unknown" : "Not Found");
                const teamsColor = teamsIsUser ? "#0f6d35" : (teamsState === "Unknown" ? "#7a1020" : "#6b7280");
                const devList = (r.devices || []).map(function (d) {
                  const exts = (d.extensions || []).join(", ") || "\u2014";
                  return "<strong>" + d.name + "</strong> <span style='color:#555;font-size:12px;'>[" + d.type + "] " + exts + "</span>";
                }).join("<br>") || "\u2014";

                const btnStyle = "display:inline-block;margin:0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;color:#fff;";
                const strikeBtn = `<button type="button" style="${btnStyle}background:#237741;" data-strike-user="${uid}">Strike Mode - Add in Both Jabber iPhone and Android</button>`;
                const tctBtn = `<button type="button" style="${btnStyle}background:#0e7490;" data-tct-user="${uid}">Add Jabber iPhone</button>`;
                const botBtn = `<button type="button" style="${btnStyle}background:#7c3aed;" data-bot-user="${uid}">Add Jabber Android</button>`;
                const notifyBtn = `<button type="button" style="${btnStyle}background:#1f7a3d;" data-notify-user="${uid}" data-notify-tel="${(r.telephone || "")}">Send New Jabber Email</button>`;
                const mobileResendBtn = `<button type="button" style="${btnStyle}background:#0f766e;" data-mobile-resend-uid="${uid}">Re-send Mobile Email</button>`;
                const offboardBtn = `<button type="button" style="${btnStyle}background:#b00020;" data-offboard-user="${uid}">Separate Employee-Delete Jabber/VM</button>`;
                const actionBtn = strikeBtn + tctBtn + botBtn + notifyBtn + mobileResendBtn + offboardBtn;

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px; font-weight:700; color:#002f6c;">' + ext + '</td>';
                html += '<td style="padding:7px 10px;">' + email + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px; font-weight:700; color:' + teamsColor + ';">' + teamsText + '</td>';
                html += '<td style="padding:7px 10px; line-height:1.6;">' + devList + '</td>';
                html += '<td style="padding:7px 10px;"><div style="display:grid;grid-template-columns:repeat(3,max-content);gap:4px;align-items:start;">' + actionBtn + '</div></td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;

              resultsEl.querySelectorAll("button[data-strike-user]").forEach(function (btn) {
                btn.addEventListener("click", function () {
                  const uid = btn.getAttribute("data-strike-user") || "";
                  const confirmed = confirm(`Open Strike Mode for ${uid} in __ENV_TEXT__?\n\nThis prepares iPhone + Android provisioning.`);
                  if (!confirmed) {
                    return;
                  }
                  if (strikeTargetInput) {
                    strikeTargetInput.value = uid;
                    strikeTargetInput.focus();
                  }
                  statusEl.textContent = `Loaded ${uid} into Strike Mode - Add in Both Jabber iPhone and Android.`;
                });
              });

              function submitAdminAction(endpoint, uid) {
                const cucmHost = "__AUTH_CUCM_HOST__";
                const cucmUser = "__AUTH_USER__";
                const cucmPass = "";

                const actionForm = document.createElement("form");
                actionForm.method = "post";
                actionForm.action = endpoint;

                const fields = {
                  cucm_host: cucmHost,
                  cucm_user: cucmUser,
                  cucm_pass: cucmPass,
                  target_user: uid,
                  back_url: "/page2",
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
                  const confirmed = confirm(`Open Offboard workflow for ${uid} in __ENV_TEXT__?\n\nThis leads to Separate Employee-Delete Jabber/VM.`);
                  if (!confirmed) {
                    return;
                  }
                  const qs = new URLSearchParams({ panel: "offboard", target_user: uid });
                  window.location.href = "/menu?" + qs.toString();
                });
              });

              resultsEl.querySelectorAll("button[data-notify-user]").forEach(function (btn) {
                btn.addEventListener("click", async function () {
                  const uid = btn.getAttribute("data-notify-user") || "";
                  const tel = btn.getAttribute("data-notify-tel") || "";
                  const cucmHost = "__AUTH_CUCM_HOST__";
                  const cucmUser = "__AUTH_USER__";
                  const cucmPass = "";
                  const origText = btn.textContent;

                  btn.disabled = true;
                  btn.textContent = "Sending...";
                  statusEl.textContent = `Sending Jabber notification for ${uid}...`;
                  try {
                    const sf = new FormData();
                    sf.append("cucm_host", cucmHost);
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
                    btn.textContent = "\u2713 Sent";
                    btn.style.background = "#166534";
                    statusEl.textContent = "Notification sent: " + (sp.detail || "Email sent successfully.");
                  } catch (err) {
                    btn.textContent = origText;
                    btn.disabled = false;
                    statusEl.textContent = "Send failed: " + ((err && err.message) || "Unknown error.");
                  }
                });
              });

              resultsEl.querySelectorAll("button[data-mobile-resend-uid]").forEach(function (btn) {
                btn.addEventListener("click", async function () {
                  const uid = btn.getAttribute("data-mobile-resend-uid") || "";
                  const cucmHost = "__AUTH_CUCM_HOST__";
                  const cucmUser = "__AUTH_USER__";
                  const cucmPass = "";
                  const origText = btn.textContent;
                  btn.disabled = true;
                  btn.textContent = "Sending...";
                  statusEl.textContent = `Sending mobile Jabber email for ${uid}...`;
                  try {
                    const sf = new FormData();
                    sf.append("cucm_host", cucmHost);
                    sf.append("cucm_user", cucmUser);
                    sf.append("cucm_pass", cucmPass);
                    sf.append("target_user", uid);
                    const sr = await fetch("/send/mobile-jabber-email", {
                      method: "POST",
                      body: sf,
                      credentials: "same-origin",
                      headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
                    });
                    const sp = await sr.json();
                    if (!sr.ok || !sp.ok) throw new Error((sp && sp.detail) || "Send failed.");
                    btn.textContent = "\u2713 Sent";
                    btn.style.background = "#166534";
                    statusEl.textContent = "Mobile email sent for " + uid + ": " + (sp.detail || "Success.");
                  } catch (err) {
                    btn.textContent = origText;
                    btn.disabled = false;
                    statusEl.textContent = "Mobile email failed: " + ((err && err.message) || "Unknown error.");
                  }
                });
              });
            } catch (err) {
              const normalized = String((err && err.message) || "").toLowerCase();
              if (
                normalized.includes("credentials expired")
                || normalized.includes("log in again")
                || normalized.includes("missing cucm credentials")
              ) {
                window.location.href = "/logout";
                return;
              }
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
            const cucmHost = "__AUTH_CUCM_HOST__";
            const cucmUser = "__AUTH_USER__";
            const cucmPass = "";

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
              cucm_host: cucmHost,
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

                const btnStyle = "display:inline-block;margin:0;padding:4px 8px;font-size:11px;font-weight:600;border-radius:5px;border:none;cursor:pointer;color:#fff;";
                const tctBtn = `<button type="button" style="${btnStyle}background:#0e7490;" data-delete-mode="tct" data-delete-user="${uid}">Delete iPhone (TCT)</button>`;
                const botBtn = `<button type="button" style="${btnStyle}background:#7c3aed;" data-delete-mode="bot" data-delete-user="${uid}">Delete Android (BOT)</button>`;
                const bothBtn = `<button type="button" style="${btnStyle}background:#b00020;" data-delete-mode="both" data-delete-user="${uid}">Delete Both</button>`;

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px;">' + email + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px; line-height:1.6;">' + devList + '</td>';
                html += '<td style="padding:7px 10px;"><div style="display:grid;grid-template-columns:repeat(2,max-content);gap:4px;align-items:start;">' + tctBtn + botBtn + bothBtn + '</div></td>';
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
          const strikeMaskLookupForm = document.getElementById("admin-strikemask-lookup-form");
          if (strikeMaskLookupForm) {
            strikeMaskLookupForm.addEventListener("submit", async function (event) {
              event.preventDefault();
              const statusEl = document.getElementById("admin-strikemask-lookup-status");
              const resultsEl = document.getElementById("admin-strikemask-lookup-results");

              statusEl.textContent = "Searching...";
              resultsEl.innerHTML = "";

              try {
                const formData = new FormData(strikeMaskLookupForm);
                const response = await fetch("/lookup/person", {
                  method: "POST",
                  body: formData,
                  credentials: "same-origin",
                });

                const payload = await response.json();

                if (!response.ok || !payload.ok) {
                  const msg = (payload.error && payload.error.message) || "Search failed.";
                  statusEl.textContent = "Error: " + msg;
                  return;
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
                html += '<th style="padding:8px 10px; text-align:left;">Action</th>';
                html += '</tr></thead><tbody>';

                results.forEach(function (r, i) {
                  const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                  const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                  const uid = r.userid || "";
                  const ext = r.primary_extension || "\u2014";
                  const btnId = "strikemask-apply-" + i;
                  const reverseBtnId = "strikemask-reverse-latest-" + i;
                  html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                  html += '<td style="padding:7px 10px;">' + name + '</td>';
                  html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                  html += '<td style="padding:7px 10px; font-weight:700; color:#002f6c;">' + ext + '</td>';
                  html += '<td style="padding:7px 10px;">'
                    + '<button type="button" id="' + btnId + '" class="mini-btn" data-user-id="' + uid + '">Apply Strike Mask</button>'
                    + '<button type="button" id="' + reverseBtnId + '" class="mini-btn" data-user-id="' + uid + '" style="margin-left:6px; background:#a63b00; color:#fff;">Reverse Strike Mask</button>'
                    + '</td>';
                  html += '</tr>';
                });

                html += '</tbody></table>';
                html += '<div id="admin-strikemask-apply-config" style="margin-top:12px;"></div>';
                resultsEl.innerHTML = html;

                const applyConfigEl = document.getElementById("admin-strikemask-apply-config");
                const escapeHtml = function (value) {
                  return String(value || "")
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/\"/g, "&quot;")
                    .replace(/'/g, "&#39;");
                };

                document.querySelectorAll('[id^="strikemask-apply-"]').forEach(function (btn) {
                  btn.addEventListener("click", async function () {
                    const userId = btn.getAttribute("data-user-id");
                    if (!userId) {
                      statusEl.textContent = "Unable to apply Strike Mask: missing user ID.";
                      return;
                    }

                    btn.disabled = true;
                    statusEl.textContent = "Loading Strike Mask options for " + userId + "...";

                    try {
                      const optionsResponse = await fetch("/strike-mask/options", {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Accept": "application/json",
                          "X-Requested-With": "XMLHttpRequest",
                        },
                        credentials: "same-origin",
                        body: new URLSearchParams({
                          cucm_host: strikeMaskLookupForm.querySelector('input[name="cucm_host"]').value,
                          cucm_user: strikeMaskLookupForm.querySelector('input[name="cucm_user"]').value,
                          cucm_pass: strikeMaskLookupForm.querySelector('input[name="cucm_pass"]').value,
                          target_user: userId,
                        }),
                      });

                      const optionsData = await optionsResponse.json();
                      if (!optionsResponse.ok || !optionsData.ok) {
                        const msg = (optionsData.error && optionsData.error.message) || optionsData.detail || "Unable to load Strike Mask options.";
                        statusEl.textContent = "Error loading options for " + userId + ": " + msg;
                        btn.disabled = false;
                        return;
                      }

                      const patterns = optionsData.available_patterns || [];
                      const devices = optionsData.devices || [];
                      if (!patterns.length) {
                        statusEl.textContent = "No available Strike Mask patterns found for apply.";
                        btn.disabled = false;
                        return;
                      }
                      if (!devices.length) {
                        statusEl.textContent = "No Jabber devices found for " + userId + ".";
                        btn.disabled = false;
                        return;
                      }

                      const patternOptions = patterns.map(function (p) {
                        const pattern = p.pattern || "";
                        const partition = p.partition || "";
                        const desc = p.description || "";
                        return '<option value="' + escapeHtml(pattern) + '">' + escapeHtml(pattern + " | " + partition + " | " + desc) + '</option>';
                      }).join("");

                      const deviceCheckboxes = devices.map(function (d, idx) {
                        const name = d.name || "";
                        const type = d.type || "";
                        const checkboxId = "strikemask-device-" + idx + "-" + name.replace(/[^a-zA-Z0-9_-]/g, "");
                        return '<label style="display:block; margin:4px 0;">'
                          + '<input type="checkbox" class="strikemask-device-checkbox" id="' + escapeHtml(checkboxId) + '" value="' + escapeHtml(name) + '" checked> '
                          + '<span>' + escapeHtml(name + " (" + type + ")") + '</span></label>';
                      }).join("");

                      applyConfigEl.innerHTML =
                        '<div style="border:1px solid #c8dbee; border-radius:8px; background:#f8fbff; padding:12px;">'
                        + '<h4 style="margin:0 0 8px 0;">Step 2 - Apply Strike Mask for ' + escapeHtml(userId) + '</h4>'
                        + '<p style="margin:0 0 8px 0; color:#355978;">Jabber Extension: <strong>' + escapeHtml(optionsData.jabber_extension || "") + '</strong></p>'
                        + '<div style="margin-bottom:8px;"><label><strong>Select Pattern:</strong></label><br><select id="admin-strikemask-pattern-select" style="width:100%; max-width:760px;">' + patternOptions + '</select></div>'
                        + '<div style="margin-bottom:10px;"><label><strong>Select Devices:</strong></label>' + deviceCheckboxes + '</div>'
                        + '<button type="button" id="admin-strikemask-apply-confirm" class="mini-btn" style="background:#005eb8; color:#fff;">Apply Selected</button>'
                        + '</div>';

                      const confirmBtn = document.getElementById("admin-strikemask-apply-confirm");
                      if (confirmBtn) {
                        confirmBtn.addEventListener("click", async function () {
                          const patternSelect = document.getElementById("admin-strikemask-pattern-select");
                          const selectedPattern = patternSelect ? (patternSelect.value || "").trim() : "";
                          const selectedDevices = Array.from(applyConfigEl.querySelectorAll(".strikemask-device-checkbox:checked"))
                            .map(function (checkbox) { return (checkbox.value || "").trim(); })
                            .filter(Boolean);

                          if (!selectedPattern) {
                            statusEl.textContent = "Select a Strike Mask pattern before applying.";
                            return;
                          }
                          if (!selectedDevices.length) {
                            statusEl.textContent = "Select at least one device before applying.";
                            return;
                          }

                          confirmBtn.disabled = true;
                          statusEl.textContent = "Applying Strike Mask for " + userId + " on selected device(s)...";

                          try {
                            const applyResponse = await fetch("/strike-mask/apply", {
                              method: "POST",
                              headers: {
                                "Content-Type": "application/x-www-form-urlencoded",
                                "Accept": "application/json",
                                "X-Requested-With": "XMLHttpRequest",
                              },
                              credentials: "same-origin",
                              body: new URLSearchParams({
                                cucm_host: strikeMaskLookupForm.querySelector('input[name="cucm_host"]').value,
                                cucm_user: strikeMaskLookupForm.querySelector('input[name="cucm_user"]').value,
                                cucm_pass: strikeMaskLookupForm.querySelector('input[name="cucm_pass"]').value,
                                target_user: userId,
                                selected_pattern: selectedPattern,
                                selected_devices: selectedDevices.join(","),
                              }),
                            });

                            const applyData = await applyResponse.json();
                            if (!applyResponse.ok || !applyData.ok) {
                              const msg = (applyData.error && applyData.error.message) || applyData.detail || "Strike Mask apply failed.";
                              statusEl.textContent = "Error applying Strike Mask for " + userId + ": " + msg;
                              confirmBtn.disabled = false;
                              return;
                            }

                            const lineStatuses = (applyData.devices_applied || []).map(function (d) {
                              return (d.device_name || "") + "=" + (d.line_mask_status || d.status || "");
                            }).join("; ");

                            btn.textContent = "Applied";
                            statusEl.textContent =
                              "✓ Applied Strike Mask for " + userId
                              + " | Pattern: " + (applyData.translation_pattern || "")
                              + " | Transform Mask: " + (applyData.new_transform_mask || "")
                              + " | Operation ID: " + (applyData.operation_id || "")
                              + (lineStatuses ? " | Line updates: " + lineStatuses : "");
                          } catch (err) {
                            statusEl.textContent = "Error applying Strike Mask for " + userId + ": " + err.message;
                            confirmBtn.disabled = false;
                          }
                        });
                      }

                      statusEl.textContent = "Loaded options. Select pattern/device(s), then click Apply Selected.";
                      btn.disabled = false;
                    } catch (err) {
                      statusEl.textContent = "Error preparing Strike Mask for " + userId + ": " + err.message;
                      btn.disabled = false;
                    }
                  });
                });

                document.querySelectorAll('[id^="strikemask-reverse-latest-"]').forEach(function (btn) {
                  btn.addEventListener("click", async function () {
                    const userId = btn.getAttribute("data-user-id");
                    if (!userId) {
                      statusEl.textContent = "Unable to reverse Strike Mask: missing user ID.";
                      return;
                    }

                    btn.disabled = true;
                    statusEl.textContent = "Finding latest active Strike Mask operation for " + userId + "...";

                    try {
                      const opsResp = await fetch("/strike-mask/in-use", {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Accept": "application/json",
                          "X-Requested-With": "XMLHttpRequest",
                        },
                        credentials: "same-origin",
                        body: new URLSearchParams({
                          cucm_host: strikeMaskLookupForm.querySelector('input[name="cucm_host"]').value,
                          cucm_user: strikeMaskLookupForm.querySelector('input[name="cucm_user"]').value,
                          cucm_pass: strikeMaskLookupForm.querySelector('input[name="cucm_pass"]').value,
                          limit: "200",
                        }),
                      });

                      const opsData = await opsResp.json();
                      if (!opsResp.ok || !opsData.ok) {
                        const msg = (opsData.error && opsData.error.message) || opsData.detail || "Unable to load active Strike Mask operations.";
                        statusEl.textContent = "Error loading active operations: " + msg;
                        btn.disabled = false;
                        return;
                      }

                      const activeOps = opsData.active_operations || [];
                      const targetOp = activeOps.find(function (op) {
                        const opUser = (op.target_user || "").trim().toLowerCase();
                        return opUser === String(userId).trim().toLowerCase();
                      });

                      if (!targetOp || !targetOp.operation_id) {
                        statusEl.textContent = "No active Strike Mask operation found for " + userId + ".";
                        btn.disabled = false;
                        return;
                      }

                      statusEl.textContent = "Reversing latest operation for " + userId + "...";
                      const reverseResp = await fetch("/strike-mask/reverse", {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Accept": "application/json",
                          "X-Requested-With": "XMLHttpRequest",
                        },
                        credentials: "same-origin",
                        body: new URLSearchParams({
                          cucm_host: strikeMaskLookupForm.querySelector('input[name="cucm_host"]').value,
                          cucm_user: strikeMaskLookupForm.querySelector('input[name="cucm_user"]').value,
                          cucm_pass: strikeMaskLookupForm.querySelector('input[name="cucm_pass"]').value,
                          operation_id: targetOp.operation_id,
                        }),
                      });

                      const reverseData = await reverseResp.json();
                      if (!reverseResp.ok || !reverseData.ok) {
                        const msg = (reverseData.error && reverseData.error.message) || reverseData.detail || "Strike Mask reversal failed.";
                        statusEl.textContent = "Error reversing Strike Mask for " + userId + ": " + msg;
                        btn.disabled = false;
                        return;
                      }

                      btn.textContent = "Reversed";
                      statusEl.textContent =
                        "✓ Reversed Strike Mask for " + userId
                        + " | Operation ID: " + (targetOp.operation_id || "")
                        + " | Pattern: " + (reverseData.translation_pattern || "");
                    } catch (err) {
                      statusEl.textContent = "Error reversing Strike Mask for " + userId + ": " + err.message;
                      btn.disabled = false;
                    }
                  });
                });
              } catch (err) {
                statusEl.textContent = "Error: " + err.message;
              }
            });
          }

          const strikeMaskListInUseBtn = document.getElementById("admin-strikemask-list-inuse");
          if (strikeMaskListInUseBtn && strikeMaskLookupForm) {
            strikeMaskListInUseBtn.addEventListener("click", async function () {
              const statusEl = document.getElementById("admin-strikemask-inuse-status");
              const resultsEl = document.getElementById("admin-strikemask-inuse-results");
              statusEl.textContent = "Loading in-use Strike Masks...";
              resultsEl.innerHTML = "";

              try {
                const response = await fetch("/strike-mask/in-use", {
                  method: "POST",
                  headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                  },
                  credentials: "same-origin",
                  body: new URLSearchParams({
                    cucm_host: strikeMaskLookupForm.querySelector('input[name="cucm_host"]').value,
                    cucm_user: strikeMaskLookupForm.querySelector('input[name="cucm_user"]').value,
                    cucm_pass: strikeMaskLookupForm.querySelector('input[name="cucm_pass"]').value,
                    limit: "200",
                  }),
                });

                const data = await response.json();
                if (!response.ok || !data.ok) {
                  const msg = (data.error && data.error.message) || data.detail || "Unable to list in-use Strike Masks.";
                  statusEl.textContent = "Error: " + msg;
                  return;
                }

                const live = data.live_in_use_patterns || [];
                const ops = data.active_operations || [];
                statusEl.textContent =
                  "In-use patterns: " + live.length
                  + " | Active operations tracked: " + ops.length;

                let html = "";

                html += '<h4 style="margin:8px 0 6px 0;">Live In-Use Patterns (CUCM)</h4>';
                if (!live.length) {
                  html += '<p style="color:#355978;">No in-use Strike Mask patterns found.</p>';
                } else {
                  html += '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
                  html += '<thead><tr style="background:#005eb8; color:#fff;">';
                  html += '<th style="padding:8px 10px; text-align:left;">Pattern</th>';
                  html += '<th style="padding:8px 10px; text-align:left;">Partition</th>';
                  html += '<th style="padding:8px 10px; text-align:left;">Description</th>';
                  html += '<th style="padding:8px 10px; text-align:left;">Called Party Transform Mask</th>';
                  html += '</tr></thead><tbody>';
                  live.forEach(function (item, i) {
                    const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                    html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                    html += '<td style="padding:7px 10px;">' + (item.pattern || "") + '</td>';
                    html += '<td style="padding:7px 10px;">' + (item.partition || "") + '</td>';
                    html += '<td style="padding:7px 10px;">' + (item.description || "") + '</td>';
                    html += '<td style="padding:7px 10px;">' + (item.called_party_transform_mask || "") + '</td>';
                    html += '</tr>';
                  });
                  html += '</tbody></table>';
                }

                html += '<h4 style="margin:12px 0 6px 0;">Active Operations (This App Session)</h4>';
                if (!ops.length) {
                  html += '<p style="color:#355978;">No active operations tracked in memory.</p>';
                } else {
                  html += '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
                  html += '<thead><tr style="background:#005eb8; color:#fff;">';
                  html += '<th style="padding:8px 10px; text-align:left;">Operation ID</th>';
                  html += '<th style="padding:8px 10px; text-align:left;">User</th>';
                  html += '<th style="padding:8px 10px; text-align:left;">Pattern</th>';
                  html += '<th style="padding:8px 10px; text-align:left;">Created</th>';
                  html += '</tr></thead><tbody>';
                  ops.forEach(function (item, i) {
                    const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                    html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                    html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (item.operation_id || "") + '</td>';
                    html += '<td style="padding:7px 10px;">' + (item.target_user || "") + '</td>';
                    html += '<td style="padding:7px 10px;">' + (item.translation_pattern || "") + '</td>';
                    html += '<td style="padding:7px 10px;">' + (item.created_at || "") + '</td>';
                    html += '</tr>';
                  });
                  html += '</tbody></table>';
                }

                resultsEl.innerHTML = html;
              } catch (err) {
                statusEl.textContent = "Error: " + err.message;
              }
            });
          }

          const strikeMaskReverseForm = document.getElementById("admin-strikemask-reverse-form");
          if (strikeMaskReverseForm) {
            strikeMaskReverseForm.addEventListener("submit", async function (event) {
              event.preventDefault();
              const opIdInput = strikeMaskReverseForm.querySelector('input[name="operation_id"]');
              const statusEl = document.getElementById("admin-strikemask-reverse-status");
              const summaryEl = document.getElementById("admin-strikemask-reverse-summary");

              const opId = (opIdInput.value || "").trim();
              if (!opId) {
                statusEl.textContent = "Operation ID is required.";
                return;
              }

              statusEl.textContent = "Reversing...";
              summaryEl.textContent = "";

              try {
                const resp = await fetch("/strike-mask/reverse", {
                  method: "POST",
                  headers: { "Content-Type": "application/x-www-form-urlencoded" },
                  body: new URLSearchParams({
                    cucm_host: strikeMaskReverseForm.querySelector('input[name="cucm_host"]').value,
                    cucm_user: strikeMaskReverseForm.querySelector('input[name="cucm_user"]').value,
                    cucm_pass: strikeMaskReverseForm.querySelector('input[name="cucm_pass"]').value,
                    operation_id: opId,
                  }),
                });
                const data = await resp.json();
                if (!data.ok) {
                  statusEl.textContent = "Error: " + (data.error || "Unknown error");
                  return;
                }

                statusEl.textContent = "✓ Strike Mask reversed successfully!";
                const reverted = data.devices_reverted || [];
                let summary = "Pattern: " + data.translation_pattern + " | Devices: " + reverted.length;
                reverted.forEach(function (dev) {
                  summary += " | " + dev.device_name + ": " + dev.status;
                });
                summaryEl.textContent = summary;
              } catch (err) {
                statusEl.textContent = "Error: " + err.message;
              }
            });
          }
        })();
      </script>

      <script>
        (function () {
          const form = document.getElementById("strikemask-upload-form");
          const statusEl = document.getElementById("strikemask-upload-status");
          const resultsEl = document.getElementById("strikemask-upload-results");

          if (!form || !statusEl || !resultsEl) {
            return;
          }

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Creating translation patterns...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              const resp = await fetch("/strike-mask-translation/upload", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
              });

              const rawText = await resp.text();
              let payload = {};
              try {
                payload = rawText ? JSON.parse(rawText) : {};
              } catch (_parseErr) {
                payload = {};
              }

              if (!resp.ok) {
                const backendMsg = (payload && payload.detail) || rawText || "Upload failed.";
                throw new Error(backendMsg);
              }

              const summary = payload.summary || {};
              statusEl.textContent = `Completed: ${summary.success_count || 0} succeeded, ${summary.failed_count || 0} failed, ${summary.total_rows || 0} total.`;
              
              const outputText = (payload.output_text || "").split("\n").filter(l => l.trim());
              let resultHtml = "<pre style='background:#f5f5f5; padding:10px; border-radius:4px; overflow-x:auto; font-size:12px; font-family:Consolas,monospace;'>";
              resultHtml += outputText.slice(0, 50).join("\\n");
              if (outputText.length > 50) {
                resultHtml += "\\n... (showing first 50 lines)";
              }
              resultHtml += "</pre>";
              
              if (payload.job_id) {
                resultHtml += `<p><a href="/job-output/${payload.job_id}" style="font-weight:700;">Download Full Results CSV</a></p>`;
              }
              
              resultsEl.innerHTML = resultHtml;
              form.reset();
            } catch (err) {
              statusEl.textContent = "Upload failed: " + ((err && err.message) || "Unknown error.");
              statusEl.style.color = "#8b1e1e";
              resultsEl.innerHTML = "";
              return;
            }
            statusEl.style.color = "#1e5f2a";
          });
        })();
      </script>

      <script>
        (function () {
          const form = document.getElementById("verasmart-lab-queue-form");
          const statusEl = document.getElementById("verasmart-lab-status");
          const runsEl = document.getElementById("verasmart-lab-runs");
          const refreshBtn = document.getElementById("verasmart-lab-refresh");

          if (!form || !statusEl || !runsEl || !refreshBtn) {
            return;
          }

          function renderRuns(runs) {
            if (!runs || !runs.length) {
              runsEl.innerHTML = "<p style='color:#355978;'>No LAB runs yet.</p>";
              return;
            }

            let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
            html += '<thead><tr style="background:#005eb8; color:#fff;">';
            html += '<th style="padding:8px 10px; text-align:left;">Created</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Run ID</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Operator</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Source</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Rows</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Status</th>';
            html += '<th style="padding:8px 10px; text-align:left;">Note</th>';
            html += '</tr></thead><tbody>';

            runs.forEach(function (run, i) {
              const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
              const rows = `${run.total_rows || 0} total / ${run.pending_rows || 0} pending`;
              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
              html += '<td style="padding:7px 10px; white-space:nowrap;">' + (run.created_at || "") + '</td>';
              html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (run.run_id || "") + '</td>';
              html += '<td style="padding:7px 10px;">' + (run.operator || "") + '</td>';
              html += '<td style="padding:7px 10px;">' + (run.source_filename || "") + '</td>';
              html += '<td style="padding:7px 10px;">' + rows + '</td>';
              html += '<td style="padding:7px 10px; font-weight:700;">' + (run.status || "") + '</td>';
              html += '<td style="padding:7px 10px;">' + (run.note || "") + '</td>';
              html += '</tr>';
            });

            html += '</tbody></table>';
            runsEl.innerHTML = html;
          }

          async function refreshRuns() {
            statusEl.textContent = "Loading LAB queue status...";
            try {
              const resp = await fetch("/verasmart/lab/queue/status", {
                method: "GET",
                credentials: "same-origin",
                headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
              });
              const payload = await resp.json();
              if (!resp.ok || !payload.ok) {
                throw new Error((payload.error && payload.error.message) || "Status load failed.");
              }
              renderRuns(payload.runs || []);
              statusEl.textContent = "LAB queue status loaded.";
            } catch (err) {
              statusEl.textContent = "Status failed: " + ((err && err.message) || "Unknown error.");
            }
          }

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Uploading LAB queue CSV...";
            try {
              const formData = new FormData(form);
              const resp = await fetch("/verasmart/lab/queue/upload", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
              });
              const payload = await resp.json();
              if (!resp.ok || !payload.ok) {
                throw new Error((payload.error && payload.error.message) || "Upload failed.");
              }
              statusEl.textContent = `Queue uploaded: ${payload.run_id || ""} (${payload.total_rows || 0} rows)`;
              form.reset();
              await refreshRuns();
            } catch (err) {
              statusEl.textContent = "Upload failed: " + ((err && err.message) || "Unknown error.");
            }
          });

          refreshBtn.addEventListener("click", async function () {
            await refreshRuns();
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

          // ── SMS Separation Email Process panel ──────────────────────────────
          (function () {
            const configLoading = document.getElementById("sep-sms-config-loading");
            const configFormWrap = document.getElementById("sep-sms-config-form-wrap");
            const runBtn = document.getElementById("sep-sms-run-btn");
            const runStatus = document.getElementById("sep-sms-run-status");
            const historyBtn = document.getElementById("sep-sms-history-btn");
            const historyLoading = document.getElementById("sep-sms-history-loading");
            const historyResults = document.getElementById("sep-sms-history-results");
            const saveBtn = document.getElementById("sep-sms-save-btn");
            const saveStatus = document.getElementById("sep-sms-save-status");
            const freqEl = document.getElementById("sep-cfg-frequency");
            const weeklyDayRow = document.getElementById("sep-cfg-weekly-day-row");

            function toggleWeeklyDay() {
              if (freqEl && weeklyDayRow) {
                weeklyDayRow.style.display = freqEl.value === "weekly" ? "" : "none";
              }
            }
            if (freqEl) freqEl.addEventListener("change", toggleWeeklyDay);

            function loadConfig() {
              if (!configLoading) return;
              configLoading.style.display = "";
              if (configFormWrap) configFormWrap.style.display = "none";
              fetch("/admin/separation-sms-report/config", { credentials: "same-origin" })
                .then(r => r.json())
                .then(data => {
                  configLoading.style.display = "none";
                  if (!configFormWrap) return;

                  const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val ?? ""; };
                  set("sep-cfg-recipient", data.recipient || "");
                  set("sep-cfg-recipient-2", data.recipient_2 || "");
                  set("sep-cfg-from", data.from_address || "");
                  set("sep-cfg-hour", data.hour ?? 8);
                  set("sep-cfg-minute", String(data.minute ?? 0).padStart(2, "0"));
                  set("sep-cfg-frequency", data.frequency || "daily");
                  set("sep-cfg-weekly-day", data.weekly_day || "monday");
                  set("sep-cfg-enabled", data.enabled ? "true" : "false");

                  toggleWeeklyDay();
                  configFormWrap.style.display = "";
                })
                .catch(() => {
                  if (configLoading) configLoading.textContent = "Failed to load settings.";
                });
            }

            if (saveBtn) {
              saveBtn.addEventListener("click", function () {
                const recipient = (document.getElementById("sep-cfg-recipient")?.value || "").trim();
                if (!recipient) {
                  if (saveStatus) saveStatus.innerHTML = '<span style="color:#b71c1c">Primary recipient is required.</span>';
                  return;
                }
                saveBtn.disabled = true;
                if (saveStatus) saveStatus.textContent = "Saving…";
                const payload = {
                  recipient,
                  recipient_2: (document.getElementById("sep-cfg-recipient-2")?.value || "").trim(),
                  from_address: (document.getElementById("sep-cfg-from")?.value || "").trim(),
                  enabled: document.getElementById("sep-cfg-enabled")?.value === "true",
                  hour: parseInt(document.getElementById("sep-cfg-hour")?.value || "8", 10),
                  minute: parseInt(document.getElementById("sep-cfg-minute")?.value || "0", 10),
                  frequency: document.getElementById("sep-cfg-frequency")?.value || "daily",
                  weekly_day: document.getElementById("sep-cfg-weekly-day")?.value || "monday",
                };
                fetch("/admin/separation-sms-report/save-config", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  credentials: "same-origin",
                  body: JSON.stringify(payload),
                })
                  .then(r => r.json())
                  .then(data => {
                    saveBtn.disabled = false;
                    if (data.ok) {
                      if (saveStatus) saveStatus.innerHTML = '<span style="color:#1b5e20;background:#e8f5e9;padding:4px 10px;border-radius:4px">✅ Saved</span>';
                    } else {
                      if (saveStatus) saveStatus.innerHTML = `<span style="color:#b71c1c">❌ ${data.error || "Save failed"}</span>`;
                    }
                  })
                  .catch(err => {
                    saveBtn.disabled = false;
                    if (saveStatus) saveStatus.innerHTML = `<span style="color:#b71c1c">Network error: ${err.message}</span>`;
                  });
              });
            }

            function loadHistory() {
              if (!historyLoading || !historyResults) return;
              historyLoading.style.display = "";
              historyResults.innerHTML = "";
              fetch("/admin/separation-sms-report/history", { credentials: "same-origin" })
                .then(r => r.json())
                .then(data => {
                  historyLoading.style.display = "none";
                  const rows = data.rows || [];
                  if (!rows.length) {
                    historyResults.innerHTML = '<p style="color:#888;font-size:13px;">No sends logged yet.</p>';
                    return;
                  }
                  let html = '<table style="width:100%;font-size:13px;border-collapse:collapse">'
                    + '<thead><tr style="background:#f5f5f5">'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Sent At</th>'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Period</th>'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Recipients</th>'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Extensions Checked</th>'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Triggered By</th>'
                    + '</tr></thead><tbody>';
                  rows.forEach((r, i) => {
                    const bg = i % 2 === 0 ? "#fff" : "#f9f9f9";
                    const extList = r.extension_deleted || "";
                    const extCount = extList && extList !== "none" ? extList.split("|").filter(Boolean).length : 0;
                    const extDisplay = extList && extList !== "none"
                      ? `<span title="${extList}">${extCount} extension${extCount !== 1 ? "s" : ""}</span>`
                      : "0 extensions";
                    html += `<tr style="background:${bg}">`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;white-space:nowrap">${r.timestamp || ""}</td>`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:12px">${r.period || ""}</td>`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:12px">${(r.account || "").replace(/\|/g, "<br>")}</td>`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee">${extDisplay}</td>`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;color:#888;font-size:12px">${r.operator || ""}</td>`
                      + `</tr>`;
                  });
                  html += "</tbody></table>";
                  historyResults.innerHTML = html;
                })
                .catch(() => {
                  if (historyLoading) historyLoading.style.display = "none";
                  if (historyResults) historyResults.innerHTML = '<p style="color:#c00;font-size:13px;">Failed to load history.</p>';
                });
            }

            if (runBtn) {
              runBtn.addEventListener("click", function () {
                runBtn.disabled = true;
                runBtn.textContent = "Running…";
                if (runStatus) runStatus.innerHTML = '<span style="color:#555;font-size:13px;">Sending report email…</span>';
                fetch("/admin/separation-sms-report/run", { method: "POST", credentials: "same-origin" })
                  .then(r => r.json())
                  .then(data => {
                    runBtn.disabled = false;
                    runBtn.textContent = "▶ Run Report Now";
                    if (runStatus) {
                      if (data.ok) {
                        runStatus.innerHTML = `<span style="color:#1b5e20;background:#e8f5e9;padding:8px 14px;border-radius:5px;font-size:13px;display:inline-block">
                          ✅ Sent to <strong>${(data.recipients || []).join(", ")}</strong> — period: ${data.date_range} — ${data.numbers_checked} extension(s) checked, ${data.numbers_found_in_sms} found in SMS platform(s)</span>`;
                        loadHistory();
                      } else {
                        runStatus.innerHTML = `<span style="color:#b71c1c;background:#ffebee;padding:8px 14px;border-radius:5px;font-size:13px;display:inline-block">❌ ${data.error || "Unknown error"}</span>`;
                      }
                    }
                  })
                  .catch(err => {
                    runBtn.disabled = false;
                    runBtn.textContent = "▶ Run Report Now";
                    if (runStatus) runStatus.innerHTML = `<span style="color:#b71c1c;font-size:13px;">Network error: ${err.message}</span>`;
                  });
              });
            }

            if (historyBtn) {
              historyBtn.addEventListener("click", loadHistory);
            }

            // Auto-load config and history when this panel becomes active.
            const panelEl = document.querySelector('[data-panel="sep-sms-report"]');
            if (panelEl) {
              const observer = new MutationObserver(mutations => {
                mutations.forEach(m => {
                  if (m.attributeName === "class" && panelEl.classList.contains("active")) {
                    loadConfig();
                    loadHistory();
                  }
                });
              });
              observer.observe(panelEl, { attributes: true });
            }
          })();

          // ── DN Number Pool Availability Report panel ─────────────────────────
          (function () {
            const cfgLoading = document.getElementById("dn-report-config-loading");
            const cfgWrap = document.getElementById("dn-report-config-form-wrap");
            const saveBtn = document.getElementById("dn-report-save-btn");
            const saveStatus = document.getElementById("dn-report-save-status");
            const runBtn = document.getElementById("dn-report-run-btn");
            const runStatus = document.getElementById("dn-report-run-status");
            const runPreview = document.getElementById("dn-report-run-preview");
            const histBtn = document.getElementById("dn-report-history-btn");
            const histLoading = document.getElementById("dn-report-history-loading");
            const histResults = document.getElementById("dn-report-history-results");

            function loadConfig() {
              if (!cfgLoading) return;
              cfgLoading.style.display = "";
              if (cfgWrap) cfgWrap.style.display = "none";
              fetch("/admin/dn-avail-report/config", { credentials: "same-origin" })
                .then(r => r.json())
                .then(data => {
                  cfgLoading.style.display = "none";
                  if (!cfgWrap) return;
                  const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val ?? ""; };
                  set("dn-cfg-recipient", data.recipient || "");
                  set("dn-cfg-recipient-2", data.recipient_2 || "");
                  set("dn-cfg-from", data.from_address || "");
                  set("dn-cfg-enabled", data.enabled ? "true" : "false");
                  set("dn-cfg-hour", data.hour ?? 8);
                  set("dn-cfg-minute", String(data.minute ?? 0).padStart(2, "0"));
                  set("dn-cfg-threshold", data.low_threshold ?? 10);
                  set("dn-cfg-cucm-host", data.cucm_host || "");
                  set("dn-cfg-cucm-user", data.cucm_user || "");
                  // Never pre-fill password; leave blank
                  set("dn-cfg-frequency", data.frequency || "daily");
                  cfgWrap.style.display = "";
                })
                .catch(() => { if (cfgLoading) cfgLoading.textContent = "Failed to load settings."; });
            }

            if (saveBtn) {
              saveBtn.addEventListener("click", function () {
                const recipient = (document.getElementById("dn-cfg-recipient")?.value || "").trim();
                if (!recipient) {
                  if (saveStatus) saveStatus.innerHTML = '<span style="color:#b71c1c">Primary recipient is required.</span>';
                  return;
                }
                saveBtn.disabled = true;
                if (saveStatus) saveStatus.textContent = "Saving…";
                const payload = {
                  recipient,
                  recipient_2: (document.getElementById("dn-cfg-recipient-2")?.value || "").trim(),
                  from_address: (document.getElementById("dn-cfg-from")?.value || "").trim(),
                  enabled: document.getElementById("dn-cfg-enabled")?.value === "true",
                  hour: parseInt(document.getElementById("dn-cfg-hour")?.value || "8", 10),
                  minute: parseInt(document.getElementById("dn-cfg-minute")?.value || "0", 10),
                  low_threshold: parseInt(document.getElementById("dn-cfg-threshold")?.value || "10", 10),
                  cucm_host: (document.getElementById("dn-cfg-cucm-host")?.value || "").trim(),
                  cucm_user: (document.getElementById("dn-cfg-cucm-user")?.value || "").trim(),
                  cucm_pass: (document.getElementById("dn-cfg-cucm-pass")?.value || "").trim(),
                  frequency: document.getElementById("dn-cfg-frequency")?.value || "daily",
                };
                fetch("/admin/dn-avail-report/save-config", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  credentials: "same-origin",
                  body: JSON.stringify(payload),
                })
                  .then(r => r.json())
                  .then(data => {
                    saveBtn.disabled = false;
                    if (data.ok) {
                      saveStatus.innerHTML = '<span style="color:#1b5e20;background:#e8f5e9;padding:4px 10px;border-radius:4px">✅ Saved</span>';
                      // Clear password field after save
                      const passEl = document.getElementById("dn-cfg-cucm-pass");
                      if (passEl) passEl.value = "";
                    } else {
                      saveStatus.innerHTML = `<span style="color:#b71c1c">❌ ${data.error || "Save failed"}</span>`;
                    }
                  })
                  .catch(err => {
                    saveBtn.disabled = false;
                    saveStatus.innerHTML = `<span style="color:#b71c1c">Network error: ${err.message}</span>`;
                  });
              });
            }

            if (runBtn) {
              runBtn.addEventListener("click", function () {
                runBtn.disabled = true;
                runBtn.textContent = "Running…";
                if (runStatus) runStatus.innerHTML = '<span style="color:#555;font-size:13px;">Querying CUCM and sending email…</span>';
                if (runPreview) runPreview.innerHTML = "";
                fetch("/admin/dn-avail-report/run", { method: "POST", credentials: "same-origin" })
                  .then(r => r.json())
                  .then(data => {
                    runBtn.disabled = false;
                    runBtn.textContent = "▶ Run Report Now";
                    if (data.ok) {
                      if (runStatus) runStatus.innerHTML = `<span style="color:#1b5e20;background:#e8f5e9;padding:8px 14px;border-radius:5px;font-size:13px;display:inline-block">✅ Sent to <strong>${(data.recipients || []).join(", ")}</strong></span>`;
                      // Render inline mini-table
                      if (runPreview && data.results) {
                        const statusColor = r => r.available === 0 ? "#b71c1c" : r.available < (data.low_threshold || 10) ? "#e65100" : "#2e7d32";
                        let t = '<table style="margin-top:12px;font-size:13px;border-collapse:collapse">'
                          + '<tr style="background:#f5f5f5"><th style="padding:6px 12px;text-align:left;border-bottom:2px solid #ddd">Type</th>'
                          + '<th style="padding:6px 12px;border-bottom:2px solid #ddd">Prefix</th>'
                          + '<th style="padding:6px 12px;border-bottom:2px solid #ddd">Available</th>'
                          + '<th style="padding:6px 12px;border-bottom:2px solid #ddd">In Use</th>'
                          + '<th style="padding:6px 12px;border-bottom:2px solid #ddd">Total</th></tr>';
                        data.results.forEach(r => {
                          t += `<tr><td style="padding:6px 12px;border-bottom:1px solid #eee;font-weight:600">${r.label}</td>`
                            + `<td style="padding:6px 12px;border-bottom:1px solid #eee;font-family:monospace">${r.prefix}xxx</td>`
                            + `<td style="padding:6px 12px;border-bottom:1px solid #eee;font-weight:700;color:${statusColor(r)}">${r.available}</td>`
                            + `<td style="padding:6px 12px;border-bottom:1px solid #eee">${r.in_use}</td>`
                            + `<td style="padding:6px 12px;border-bottom:1px solid #eee">${r.total}</td></tr>`;
                        });
                        t += "</table>";
                        runPreview.innerHTML = t;
                      }
                      loadHistory();
                    } else {
                      if (runStatus) runStatus.innerHTML = `<span style="color:#b71c1c;background:#ffebee;padding:8px 14px;border-radius:5px;font-size:13px;display:inline-block">❌ ${data.error || "Unknown error"}</span>`;
                    }
                  })
                  .catch(err => {
                    runBtn.disabled = false;
                    runBtn.textContent = "▶ Run Report Now";
                    if (runStatus) runStatus.innerHTML = `<span style="color:#b71c1c;font-size:13px;">Network error: ${err.message}</span>`;
                  });
              });
            }

            function loadHistory() {
              if (!histLoading || !histResults) return;
              histLoading.style.display = "";
              histResults.innerHTML = "";
              fetch("/admin/dn-avail-report/history", { credentials: "same-origin" })
                .then(r => r.json())
                .then(data => {
                  histLoading.style.display = "none";
                  const rows = data.rows || [];
                  if (!rows.length) { histResults.innerHTML = '<p style="color:#888;font-size:13px;">No sends logged yet.</p>'; return; }
                  let html = '<table style="width:100%;font-size:13px;border-collapse:collapse">'
                    + '<thead><tr style="background:#f5f5f5">'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Sent At</th>'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Summary</th>'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Recipients</th>'
                    + '<th style="padding:7px 10px;text-align:left;border-bottom:2px solid #ddd">Triggered By</th>'
                    + '</tr></thead><tbody>';
                  rows.forEach((r, i) => {
                    const bg = i % 2 === 0 ? "#fff" : "#f9f9f9";
                    html += `<tr style="background:${bg}">`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;white-space:nowrap">${r.timestamp || ""}</td>`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:12px">${r.summary || ""}</td>`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;font-size:12px">${(r.account || "").replace(/\|/g, "<br>")}</td>`
                      + `<td style="padding:6px 10px;border-bottom:1px solid #eee;color:#888;font-size:12px">${r.operator || ""}</td>`
                      + `</tr>`;
                  });
                  html += "</tbody></table>";
                  histResults.innerHTML = html;
                })
                .catch(() => {
                  if (histLoading) histLoading.style.display = "none";
                  if (histResults) histResults.innerHTML = '<p style="color:#c00;font-size:13px;">Failed to load history.</p>';
                });
            }

            if (histBtn) histBtn.addEventListener("click", loadHistory);

            const dnPanelEl = document.querySelector('[data-panel="dn-avail-report"]');
            if (dnPanelEl) {
              const obs = new MutationObserver(mutations => {
                mutations.forEach(m => {
                  if (m.attributeName === "class" && dnPanelEl.classList.contains("active")) {
                    loadConfig();
                    loadHistory();
                  }
                });
              });
              obs.observe(dnPanelEl, { attributes: true });
            }
          })();

        })();
      </script>
        </section>
      </div>
    </main>
  </body>
</html>
""".replace("__AUTH_USER__", auth_user).replace("__AUTH_CUCM_HOST__", escape(auth_cucm_host)).replace("__ENV_TEXT__", escape(env_text)).replace("__ENV_CLASS__", env_css_class).replace("__HAS_CACHED_CUCM_PASS__", "true" if has_cached_cucm_pass else "false").replace("__CREDENTIAL_EXPIRES_AT_MS__", str(credential_expires_at_ms))

  return HTMLResponse(
    content=html,
    headers={
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "Pragma": "no-cache",
      "Expires": "0",
    },
  )


@app.get("/page3", response_class=HTMLResponse)
def page3_twilio_items(request: Request):
  session = _get_auth_session(request) or {}
  now_epoch = time.time()
  session_username = str(session.get("username", ""))
  if not _is_admin_user(session_username):
    return HTMLResponse(
      content="<h3>403 Forbidden</h3><p>You are not authorized to access SMS Item Menu.</p>",
      status_code=403,
    )

  auth_user = escape(session_username)
  auth_cucm_host = str(session.get("cucm_host", ""))
  has_cached_cucm_pass = _has_valid_cached_secret(session, "cucm_pass", now_epoch)
  if not has_cached_cucm_pass:
    _page3_sid = request.cookies.get(SESSION_COOKIE_NAME, "")
    if _page3_sid:
      has_cached_cucm_pass = bool((AUTH_SESSION_SECRETS.get(_page3_sid, {}).get("cucm_pass", "") or "").strip())
  credential_expires_at = float(session.get("credential_expires_at", 0) or 0)
  credential_expires_at_ms = int(credential_expires_at * 1000) if (has_cached_cucm_pass and credential_expires_at > 0) else 0
  env_text, env_css_class = _get_environment_label(auth_cucm_host)
  settings = _load_settings()
  default_twilio_loa_recipient_name = (settings.get("twilio_loa_recipient_name", "") or "").strip()
  default_twilio_loa_recipient_email = (settings.get("twilio_loa_recipient_email", "") or "").strip()
  default_twilio_loa_recipient_phone = (settings.get("twilio_loa_recipient_phone", "") or "").strip()
  sms_look_enabled = SMS_NUMBER_LOOKUP_ENABLED
  sms_experimental_enabled = _feature_enabled(
    SMS_EXPERIMENTAL_MENU_ENABLED,
    lab_only=(SMS_EXPERIMENTAL_MENU_LAB_ONLY and PREVIEW_FEATURES_LAB_ONLY_DEFAULT),
    cucm_host=auth_cucm_host,
  )

  sms_look_menu_html = ""
  sms_look_panel_html = ""
  sms_experimental_menu_html = ""
  sms_experimental_panel_html = ""
  twilio_lookup_btn_active_class = " active" if not sms_look_enabled else ""
  if sms_look_enabled:
    sms_look_menu_html = '<button type="button" class="portal-nav-btn active" data-panel="sms-number-look">SMS Number Lookup</button>'
    sms_look_panel_html = """
      <section class="tool-panel active" data-panel="sms-number-look">
          <div class="panel">
            <h3>SMS Number Lookup</h3>
            <p>Lookup by name or number. This checks all platforms: Twilio AMIEWeb, Twilio Salesforce Enterprise Org Prod, and Aerialink Classic.</p>

            <form id="sms-look-name-form">
              <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <div class="search-filter-row">
                <input name="last_name" placeholder="Last Name *" required>
                <input name="first_name" placeholder="First Name (optional)">
                <button type="submit">Lookup by Name</button>
              </div>
            </form>
            <p id="sms-look-name-status" style="color:#2c5c8a; min-height:18px;">Enter a last name to search SMS platform presence.</p>

            <hr style="margin: 18px 0; border: none; border-top: 1px solid #ddd;">

            <form id="sms-look-number-form">
              <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <div class="search-filter-row">
                <input name="phone_number" placeholder="Telephone (10 digits)" pattern="^\\d{10}$" title="Enter exactly 10 digits" required>
                <button type="submit">Lookup by Number</button>
              </div>
            </form>
            <p id="sms-look-number-status" style="color:#2c5c8a; min-height:18px;"></p>

            <div id="sms-look-results" style="overflow-x:auto;"></div>
          </div>
        </section>
"""

  if sms_experimental_enabled:
    sms_experimental_menu_html = '<button type="button" class="portal-nav-btn" data-panel="sms-experimental-lab">SMS Experimental (LAB)</button>'
    sms_experimental_panel_html = """
      <section class="tool-panel" data-panel="sms-experimental-lab">
        <div class="panel">
          <h3>SMS Experimental (LAB)</h3>
          <p class="preview-banner">Preview only. LAB-only feature flag is enabled. Keep disabled in PROD until validation is complete.</p>
          <p>This panel is intentionally feature-flagged and LAB-only. Use it for future integrations after API feasibility is validated.</p>
        </div>
      </section>
"""

  html = """
<html>
  <head>
    <title>SMS Item Menu - Voice Operations Portal</title>
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

      .topbar-status {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: center;
      }

      .topbar-status > * {
        display: inline-flex;
        align-items: center;
        min-height: 32px;
        padding: 6px 10px;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.35);
        box-sizing: border-box;
        font-size: 11px;
        font-weight: 700;
        line-height: 1.1;
      }

      .topbar-auth-pill {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
      }

      .topbar-status .env-banner {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
        box-shadow: none;
      }

      .topbar-status .session-timer {
        background: linear-gradient(180deg, #fff4df, #ffdca3);
        color: #6a3c00;
        border-color: #f0b44a;
        box-shadow: 0 6px 12px rgba(198, 138, 18, 0.22);
      }

      .topbar-status .env-banner.env-banner-prod,
      .topbar-status .env-banner.env-banner-lab {
        background: rgba(255, 255, 255, 0.12);
        color: #fff;
        border-color: rgba(255, 255, 255, 0.35);
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

      .topbar-btn-logout {
        color: #fff;
        background: linear-gradient(180deg, #cb3b2f, #9f2018);
        border-color: #f0a79c;
      }

      .topbar-btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 8px 18px rgba(0, 0, 0, 0.16);
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

      .portal-shell {
        display: grid;
        grid-template-columns: 244px minmax(0, 1fr);
        gap: 10px;
        align-items: start;
        margin-top: 8px;
      }

      .portal-sidebar {
        position: sticky;
        top: 54px;
        background: linear-gradient(180deg, rgba(0, 47, 108, 0.97), rgba(7, 75, 138, 0.96));
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 12px;
        padding: 8px;
        box-shadow: 0 18px 36px rgba(0, 47, 108, 0.18);
      }

      .portal-sidebar h4 {
        margin: 4px 6px 8px 6px;
        color: #fff;
        font-size: 13px;
        letter-spacing: 0.3px;
      }

      .portal-nav {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .portal-nav-btn {
        width: 100%;
        text-align: left;
        background: rgba(255, 255, 255, 0.09);
        color: rgba(255, 255, 255, 0.94);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 8px;
        padding: 7px 8px;
        font-size: 12px;
        line-height: 1.25;
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

      h3 {
        margin: 10px 0 6px 0;
        color: var(--amn-navy);
        font-size: 18px;
      }

      p {
        margin: 0 0 8px 0;
        color: var(--amn-text-soft);
        font-size: 13px;
        line-height: 1.5;
      }

      input, textarea, button {
        border-radius: 10px;
        border: 1px solid var(--amn-border);
      }

      input, textarea {
        min-height: 32px;
        padding: 5px 9px;
        width: min(520px, 100%);
        background: rgba(255, 255, 255, 0.96);
      }

      input:focus, textarea:focus {
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

      .search-filter-row {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-bottom: 14px;
      }

      .search-filter-row input {
        flex: 0 0 auto;
        width: 180px;
        padding: 8px 10px;
        border: 1px solid rgba(0, 47, 108, 0.2);
        border-radius: 6px;
        font-size: 14px;
      }

      .search-filter-row button {
        flex: 0 0 auto;
        padding: 8px 20px;
        background: linear-gradient(135deg, #0f5db8 0%, #0a3f7d 100%);
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-weight: 600;
        font-size: 14px;
      }

      .search-filter-row button:hover {
        background: linear-gradient(135deg, #0a3f7d 0%, #072f5f 100%);
      }

      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
        margin: 8px 0;
      }

      thead tr {
        background: var(--amn-blue);
        color: #fff;
      }

      th {
        padding: 8px 10px;
        text-align: left;
        font-weight: 700;
      }

      td {
        padding: 7px 10px;
        border-bottom: 1px solid var(--amn-border);
      }

      tbody tr {
        background: var(--amn-ice);
      }

      tbody tr:nth-child(even) {
        background: #ffffff;
      }

      .preview-banner {
        margin: 8px 0 10px 0;
        padding: 8px 10px;
        border-radius: 8px;
        border: 1px solid #f0b44a;
        background: #fff4df;
        color: #6a3c00;
        font-weight: 700;
      }

      .env-action-pill {
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

      @media (max-width: 980px) {
        .portal-shell {
          grid-template-columns: 1fr;
        }

        .portal-sidebar {
          position: static;
        }

        .portal-nav {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
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
      <div class="topbar-status">
        <span class="topbar-auth-pill">Authenticated Operator: __AUTH_USER__</span>
        <div class="env-banner __ENV_CLASS__">__ENV_TEXT__</div>
        <div id="session-timer-banner" class="session-timer" aria-live="polite" style="display:none;">
          <span class="timer-label">Auto logout in:</span>
          <span id="session-timer-remaining" class="timer-value"></span>
        </div>
      </div>
      <div class="topbar-actions">
        <a class="topbar-btn topbar-btn-logout" href="/logout">Log Out</a>
      </div>
    </header>

    <main class="content">
    <section class="page-hero">
      <div class="page-title-row">
        <div class="page-title-block">
          <h2 class="page-title">SMS Item Menu</h2>
          <p class="page-subtitle">Manage Twilio numbers and inbound verification patterns for the organization.</p>
        </div>
      </div>
      <div class="hero-link-grid">
        <a class="hero-link-card" href="/page2">
          <strong>← Back to Administrative Items</strong>
        </a>
      </div>
    </section>

    <div class="portal-shell">
      <aside class="portal-sidebar">
        <h4>Twilio Menu</h4>
        <div class="portal-nav">
          __SMS_LOOK_MENU__
          __SMS_EXPERIMENTAL_MENU__
          <button type="button" class="portal-nav-btn__TWILIO_LOOKUP_ACTIVE_CLASS__" data-panel="twilio-lookup">Twilio Number Lookup - AMIEWeb</button>
          <button type="button" class="portal-nav-btn" data-panel="twilio-sms-hosting">Twilio SMS Hosting - AMIEWeb (Developer Preview - NOT ACTIVE YET)</button>
          <button type="button" class="portal-nav-btn" data-panel="twilio-lookup-sfdc">Twilio Number Lookup - Salesforce Enterprise Org Prod</button>
          <button type="button" class="portal-nav-btn" data-panel="twilio-phimane">Twilio Verification - Phimane</button>
          <button type="button" class="portal-nav-btn" data-panel="twilio-lauraa">Twilio Verification - LauraA</button>
          <button type="button" class="portal-nav-btn" data-panel="aerialink-amieclassic">Aerialink SMS-AMIEClassic Lookup</button>
        </div>
      </aside>

      <section class="portal-main">
        __SMS_LOOK_PANEL__
        __SMS_EXPERIMENTAL_PANEL__
        <section class="tool-panel" data-panel="twilio-lookup">
          <div class="panel">
            <h3>Twilio Number Lookup - AMIEWeb</h3>
            <p>Search employees by name, then lookup their Twilio number information.</p>
            <form id="twilio-lookup-search-form">
              <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <div class="search-filter-row">
                <input name="last_name" placeholder="Last Name *" required>
                <input name="first_name" placeholder="First Name (optional)">
                <button type="submit">Search by Name</button>
              </div>
            </form>
            <p id="twilio-lookup-search-status" style="color:#2c5c8a; min-height:18px;">Enter a last name to find employees.</p>
            <div id="twilio-lookup-search-results" style="overflow-x:auto;"></div>

            <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
            <h4 style="margin-bottom: 10px; color: #2c5c8a;">Direct Number Lookup</h4>
            <form id="twilio-number-lookup-form">
              <div class="search-filter-row">
                <input name="phone_number" placeholder="Telephone (10 digits)" pattern="^\\d{10}$" title="Enter exactly 10 digits" required>
                <button type="submit">Check Twilio Status</button>
              </div>
            </form>
            <p id="twilio-number-lookup-status" style="color:#2c5c8a; min-height:18px;"></p>
            <div id="twilio-number-lookup-results" style="overflow-x:auto;"></div>
          </div>
        </section>

        <section class="tool-panel" data-panel="twilio-sms-hosting">
          <div class="panel">
            <h3>Twilio SMS Hosting - AMIEWeb (Developer Preview - NOT ACTIVE YET)</h3>
              <p style="color:#a01818; font-weight:700;">This function is currently not active pending Twilio Developer Preview enablement.</p>
              <p>Host SMS for one or more Twilio numbers in AMIEWeb. This updates SMS webhook fields only and does not modify voice webhook settings. If SMS URL is left blank, the default AMN listener URL is used.</p>
            <form id="twilio-sms-host-form">
              <div class="search-filter-row" style="align-items:flex-start;">
                <textarea name="phone_numbers" rows="5" placeholder="Phone numbers (one or more), separated by commas or new lines&#10;Example: 8585236648" required></textarea>
              </div>
              <div class="search-filter-row">
                  <input name="sms_url" placeholder="SMS URL (optional; blank uses default)" value="__DEFAULT_TWILIO_SMS_URL__">
                <input name="sms_method" placeholder="SMS Method (POST/GET)" value="POST">
              </div>
              <div class="search-filter-row">
                <input name="friendly_name" placeholder="Friendly Name (optional custom). Blank = auto YYYYMMDD_X">
              </div>
              <div class="search-filter-row">
                <input name="loa_recipient_name" placeholder="LOA Recipient Name (default from Settings)" value="__DEFAULT_TWILIO_LOA_RECIPIENT_NAME__">
                <input name="loa_recipient_email" placeholder="LOA Recipient Email (default from Settings)" value="__DEFAULT_TWILIO_LOA_RECIPIENT_EMAIL__">
              </div>
              <div class="search-filter-row">
                <input name="loa_recipient_phone" placeholder="LOA Recipient Phone (default from Settings)" value="__DEFAULT_TWILIO_LOA_RECIPIENT_PHONE__">
              </div>
              <div class="search-filter-row">
                <select name="loa_mode" style="max-width:260px;">
                  <option value="single" selected>LOA Mode: Single LOA for Batch</option>
                  <option value="per_number">LOA Mode: Per Number</option>
                </select>
                <input name="loa_batch_reference" placeholder="LOA Batch Reference (optional; e.g., DocuSign Envelope ID)">
              </div>
              <div class="search-filter-row">
                <input name="sms_fallback_url" placeholder="SMS Fallback URL (optional)">
                <input name="sms_fallback_method" placeholder="SMS Fallback Method (POST/GET)" value="POST">
              </div>
              <div class="search-filter-row">
                <input name="status_callback_url" placeholder="Status Callback URL (optional)">
                <input name="status_callback_method" placeholder="Status Callback Method (POST/GET)" value="POST">
                <button type="submit">Apply SMS Hosting</button>
              </div>
            </form>
            <p id="twilio-sms-host-status" style="color:#2c5c8a; min-height:18px;">Required fields: phone number(s), SMS method. Friendly Name can be custom, or blank for auto YYYYMMDD_X. LOA contact defaults come from Settings.</p>
            <div id="twilio-sms-host-results" style="overflow-x:auto;"></div>
            <div id="twilio-sms-verify-queue" style="margin-top:14px;"></div>
            <hr style="margin: 16px 0; border: none; border-top: 1px solid #ddd;">
            <h4 style="margin:0 0 8px 0; color:#2c5c8a;">Recent Friendly Name Status</h4>
            <form id="twilio-friendly-status-form">
              <div class="search-filter-row">
                <input name="friendly_name" placeholder="Friendly Name (leave blank for recent)">
                <button type="submit">Refresh Status</button>
                <a href="/download/twilio-sms-hosting-audit" style="display:inline-block;padding:8px 10px;background:#385977;color:#fff;border-radius:6px;text-decoration:none;font-weight:700;">Download SMS Hosting Audit CSV</a>
              </div>
            </form>
            <p id="twilio-friendly-status-status" style="color:#2c5c8a; min-height:18px;">Use this for long-running completion checks (minutes/hours/days).</p>
            <div id="twilio-friendly-status-results" style="overflow-x:auto;"></div>
          </div>
        </section>

        <section class="tool-panel" data-panel="twilio-lookup-sfdc">
          <div class="panel">
            <h3>Twilio Number Lookup - Salesforce Enterprise Org Prod</h3>
            <p>Search employees by name, then lookup their Twilio number information from the Salesforce Enterprise Org Prod sub-account.</p>
            <form id="twilio-lookup-sfdc-search-form">
              <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <div class="search-filter-row">
                <input name="last_name" placeholder="Last Name *" required>
                <input name="first_name" placeholder="First Name (optional)">
                <button type="submit">Search by Name</button>
              </div>
            </form>
            <p id="twilio-lookup-sfdc-search-status" style="color:#2c5c8a; min-height:18px;">Enter a last name to find employees.</p>
            <div id="twilio-lookup-sfdc-search-results" style="overflow-x:auto;"></div>

            <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
            <h4 style="margin-bottom: 10px; color: #2c5c8a;">Direct Number Lookup</h4>
            <form id="twilio-number-lookup-sfdc-form">
              <div class="search-filter-row">
                <input name="phone_number" placeholder="Telephone (10 digits)" pattern="^\\d{10}$" title="Enter exactly 10 digits" required>
                <button type="submit">Check Twilio Status</button>
              </div>
            </form>
            <p id="twilio-number-lookup-sfdc-status" style="color:#2c5c8a; min-height:18px;"></p>
            <div id="twilio-number-lookup-sfdc-results" style="overflow-x:auto;"></div>
          </div>
        </section>

        <section class="tool-panel" data-panel="twilio-phimane">
          <div class="panel">
            <h3>Twilio-Inbound-Verificaton-Phimane</h3>
            <p>Targets only the translation pattern with exact description <strong>Twilio Number Verification to Phimane 8585236648</strong>. No other translation pattern fields are changed.</p>
            <form id="admin-twilio-verify-phimane-form">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <input type="hidden" name="profile_key" value="phimane">
              <p>Set Translation Pattern to:</p>
              <input name="target_pattern" placeholder="Enter target pattern" required>
              <div style="display:flex; gap:8px;">
                <button type="submit">Apply Target Pattern</button>
                <button type="button" id="admin-twilio-verify-phimane-restore" style="background:linear-gradient(180deg,#19743a,#145c2e);">Restore to 8585236648</button>
              </div>
            </form>
            <p id="admin-twilio-verify-phimane-status" style="color:#2c5c8a; min-height:18px;">Use Apply to switch temporarily, then Restore to return to 8585236648.</p>
            <p id="admin-twilio-verify-phimane-summary" style="color:#355978; min-height:18px;"></p>
          </div>
        </section>

        <section class="tool-panel" data-panel="twilio-lauraa">
          <div class="panel">
            <h3>Twilio-Inbound-Verificaton-LauraA</h3>
            <p>Targets only the translation pattern with exact description <strong>Twilio Number Verification to LauraA 8583503289</strong>. No other translation pattern fields are changed.</p>
            <form id="admin-twilio-verify-lauraa-form">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <input type="hidden" name="profile_key" value="lauraa">
              <p>Set Translation Pattern to:</p>
              <input name="target_pattern" placeholder="Enter target pattern" required>
              <div style="display:flex; gap:8px;">
                <button type="submit">Apply Target Pattern</button>
                <button type="button" id="admin-twilio-verify-lauraa-restore" style="background:linear-gradient(180deg,#19743a,#145c2e);">Restore to 8583503289</button>
              </div>
            </form>
            <p id="admin-twilio-verify-lauraa-status" style="color:#2c5c8a; min-height:18px;">Use Apply to switch temporarily, then Restore to return to 8583503289.</p>
            <p id="admin-twilio-verify-lauraa-summary" style="color:#355978; min-height:18px;"></p>
          </div>
        </section>

        <section class="tool-panel" data-panel="aerialink-amieclassic">
          <div class="panel">
            <h3>Aerialink SMS-AMIEClassic Lookup</h3>
            <p>Search CUCM users by name, then check if their telephone number is provisioned on your Aerialink account.</p>
            <form id="aerialink-amieclassic-search-form">
              <input type="hidden" name="cucm_host" value="__AUTH_CUCM_HOST__">
              <input type="hidden" name="cucm_user" value="__AUTH_USER__">
              <input type="hidden" name="cucm_pass" value="">
              <div class="search-filter-row">
                <input name="last_name" placeholder="Last Name *" required>
                <input name="first_name" placeholder="First Name (optional)">
                <button type="submit">Search by Name</button>
              </div>
            </form>
            <p id="aerialink-amieclassic-search-status" style="color:#2c5c8a; min-height:18px;">Enter a last name to find employees.</p>
            <div id="aerialink-amieclassic-search-results" style="overflow-x:auto;"></div>

            <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
            <h4 style="margin-bottom: 10px; color: #2c5c8a;">Direct Number Lookup</h4>
            <form id="aerialink-number-lookup-form">
              <div class="search-filter-row">
                <input name="phone_number" placeholder="Telephone (10 digits)" pattern="^\\d{10}$" title="Enter exactly 10 digits" required>
                <button type="submit">Check Aerialink Status</button>
              </div>
            </form>
            <p id="aerialink-number-lookup-status" style="color:#2c5c8a; min-height:18px;"></p>
            <div id="aerialink-number-lookup-results" style="overflow-x:auto;"></div>
          </div>
        </section>
      </section>
    </div>

    <script>
      (function () {
        const hasCachedCucmPassword = __HAS_CACHED_CUCM_PASS__;
        const credentialExpiresAtMs = __CREDENTIAL_EXPIRES_AT_MS__;
        const sessionTimerBanner = document.getElementById("session-timer-banner");
        const sessionTimerRemaining = document.getElementById("session-timer-remaining");

        function formatTimerValue(totalSeconds) {
          const safe = Math.max(0, Math.floor(totalSeconds));
          const hours = Math.floor(safe / 3600);
          const minutes = Math.floor((safe % 3600) / 60);
          const seconds = safe % 60;
          return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
        }

        function startCredentialTimer() {
          if (!hasCachedCucmPassword || !sessionTimerBanner || !sessionTimerRemaining || !credentialExpiresAtMs) {
            return;
          }

          sessionTimerBanner.style.display = "flex";

          const updateTimer = () => {
            const remainingMs = credentialExpiresAtMs - Date.now();
            if (remainingMs <= 0) {
              sessionTimerRemaining.textContent = "Expired";
              window.location.href = "/logout";
              return;
            }
            sessionTimerRemaining.textContent = formatTimerValue(remainingMs / 1000);
          };

          updateTimer();
          window.setInterval(updateTimer, 1000);
        }

        startCredentialTimer();

        // Panel navigation
        const navButtons = Array.from(document.querySelectorAll(".portal-nav-btn"));
        const panels = Array.from(document.querySelectorAll(".tool-panel"));

        function showPanel(panelName) {
          if (!panelName) {
            return false;
          }
          const targetPanel = document.querySelector(`.tool-panel[data-panel="${panelName}"]`);
          const targetButton = document.querySelector(`.portal-nav-btn[data-panel="${panelName}"]`);
          if (!targetPanel || !targetButton) {
            return false;
          }

          panels.forEach((panel) => panel.classList.remove("active"));
          navButtons.forEach((button) => button.classList.remove("active"));
          targetPanel.classList.add("active");
          targetButton.classList.add("active");
          return true;
        }

        navButtons.forEach((btn) => {
          btn.addEventListener("click", function () {
            const panelName = this.getAttribute("data-panel");
            showPanel(panelName);
          });
        });

        const panelFromQuery = new URLSearchParams(window.location.search).get("panel");
        if (!showPanel(panelFromQuery)) {
          const firstButton = navButtons.find((btn) => !!btn.getAttribute("data-panel"));
          if (firstButton) {
            showPanel(firstButton.getAttribute("data-panel"));
          }
        }

        // Twilio Inbound Verification Panel Handler
        function initTwilioInboundVerificationPanel(config) {
          const form = document.getElementById(config.formId);
          const statusEl = document.getElementById(config.statusId);
          const summaryEl = document.getElementById(config.summaryId);
          const restoreBtn = document.getElementById(config.restoreButtonId);
          if (!form || !statusEl || !summaryEl || !restoreBtn) {
            return;
          }

          let countdownTimer = null;

          function stopCountdown() {
            if (countdownTimer) {
              window.clearInterval(countdownTimer);
              countdownTimer = null;
            }
          }

          function formatCountdown(msLeft) {
            const safeMs = Math.max(0, Math.floor(msLeft));
            const totalSeconds = Math.floor(safeMs / 1000);
            const minutes = Math.floor(totalSeconds / 60);
            const seconds = totalSeconds % 60;
            return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
          }

          function startCountdown(restoreAtEpochMs) {
            stopCountdown();
            if (!restoreAtEpochMs) {
              return;
            }

            const render = () => {
              const msLeft = restoreAtEpochMs - Date.now();
              if (msLeft <= 0) {
                stopCountdown();
                summaryEl.textContent = "Fail-safe timer elapsed. Pattern should now be auto-restored to the original number.";
                return;
              }
              summaryEl.textContent = `Auto-restore in ${formatCountdown(msLeft)}. Fail-safe will revert to original if no manual restore is pressed.`;
            };

            render();
            countdownTimer = window.setInterval(render, 1000);
          }

          async function submitRequest(mode) {
            statusEl.textContent = mode === "restore" ? "Restoring default pattern..." : "Updating pattern...";
            if (mode === "restore") {
              stopCountdown();
            }
            summaryEl.textContent = "";

            const formData = new FormData(form);
            if (mode === "restore") {
              formData.set("restore_default", "1");
            } else {
              formData.set("restore_default", "0");
            }

            try {
              const response = await fetch("/translation-pattern/twilio-inbound-verification", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                const msg = (payload.error && payload.error.message) || "Update failed.";
                throw new Error(msg);
              }

              const changeWord = payload.changed ? "Updated" : "No change";
              statusEl.textContent = `${changeWord}: ${payload.old_pattern || ""} -> ${payload.new_pattern || ""}`;
              const detailSummary = `Description: ${payload.description || ""} | Partition: ${payload.route_partition || ""} | Called Party Transform Mask: ${payload.called_party_transform_mask || ""}`;

              if (payload.auto_restore_enabled && payload.auto_restore_at_epoch_ms) {
                startCountdown(payload.auto_restore_at_epoch_ms);
              } else {
                stopCountdown();
                summaryEl.textContent = `No auto-restore timer active. ${detailSummary}`;
              }
            } catch (err) {
              statusEl.textContent = "Action failed: " + ((err && err.message) || "Unknown error.");
              stopCountdown();
            }
          }

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            await submitRequest("apply");
          });

          restoreBtn.addEventListener("click", async function () {
            await submitRequest("restore");
          });
        }

        initTwilioInboundVerificationPanel({
          formId: "admin-twilio-verify-phimane-form",
          statusId: "admin-twilio-verify-phimane-status",
          summaryId: "admin-twilio-verify-phimane-summary",
          restoreButtonId: "admin-twilio-verify-phimane-restore",
        });

        initTwilioInboundVerificationPanel({
          formId: "admin-twilio-verify-lauraa-form",
          statusId: "admin-twilio-verify-lauraa-status",
          summaryId: "admin-twilio-verify-lauraa-summary",
          restoreButtonId: "admin-twilio-verify-lauraa-restore",
        });

        // SMS Number Lookup - unified lookup across Twilio AMIEWeb, Twilio Salesforce, and Aerialink.
        (function () {
          const nameForm = document.getElementById("sms-look-name-form");
          const numberForm = document.getElementById("sms-look-number-form");
          const nameStatusEl = document.getElementById("sms-look-name-status");
          const numberStatusEl = document.getElementById("sms-look-number-status");
          const resultsEl = document.getElementById("sms-look-results");

          if (!nameForm || !numberForm || !nameStatusEl || !numberStatusEl || !resultsEl) {
            return;
          }

          function renderRows(rows) {
            if (!rows || !rows.length) {
              resultsEl.innerHTML = "";
              return;
            }

            let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
            html += '<thead><tr style="background:#005eb8; color:#fff;">';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Extension</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">SMS Number</th>';
            html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Configured In</th>';
            html += '</tr></thead><tbody>';

            rows.forEach(function (row, i) {
              const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
              html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
              html += '<td style="padding:7px 10px;">' + (row.display_name || "-") + '</td>';
              html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (row.extension || "-") + '</td>';
              html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (row.sms_number || "-") + '</td>';
              html += '<td style="padding:7px 10px;">' + (row.configured_in || "Not Found") + '</td>';
              html += '</tr>';
            });

            html += '</tbody></table>';
            resultsEl.innerHTML = html;
          }

          nameForm.addEventListener("submit", async function (event) {
            event.preventDefault();
            nameStatusEl.textContent = "Searching by name across all SMS platforms...";
            numberStatusEl.textContent = "";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(nameForm);
              const response = await fetch("/lookup/sms-number-look", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
              });
              const rawText = await response.text();
              let payload = {};
              try {
                payload = rawText ? JSON.parse(rawText) : {};
              } catch (_) {
                payload = { ok: false, detail: `Unexpected response (HTTP ${response.status}).` };
              }
              if (!response.ok || !payload.ok) {
                throw new Error((payload.error && payload.error.message) || payload.detail || "Lookup failed.");
              }

              const rows = payload.results || [];
              if (!rows.length) {
                nameStatusEl.textContent = "No users found.";
                renderRows([]);
                return;
              }

              nameStatusEl.textContent = `Found ${rows.length} result(s).`;
              renderRows(rows);
            } catch (err) {
              nameStatusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });

          numberForm.addEventListener("submit", async function (event) {
            event.preventDefault();
            numberStatusEl.textContent = "Searching by number across all SMS platforms...";
            nameStatusEl.textContent = "";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(numberForm);
              const response = await fetch("/lookup/sms-number-look", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" },
              });
              const rawText = await response.text();
              let payload = {};
              try {
                payload = rawText ? JSON.parse(rawText) : {};
              } catch (_) {
                payload = { ok: false, detail: `Unexpected response (HTTP ${response.status}).` };
              }
              if (!response.ok || !payload.ok) {
                throw new Error((payload.error && payload.error.message) || payload.detail || "Lookup failed.");
              }

              const rows = payload.results || [];
              numberStatusEl.textContent = rows.length ? `Found ${rows.length} result(s).` : "Number not found in SMS platforms.";
              renderRows(rows);
            } catch (err) {
              numberStatusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Twilio Lookup Form Handler
        (function () {
          const form = document.getElementById("twilio-lookup-search-form");
          const statusEl = document.getElementById("twilio-lookup-search-status");
          const resultsEl = document.getElementById("twilio-lookup-search-results");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Searching...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              formData.append("include_twilio_lookup", "1");
              const response = await fetch("/lookup/person", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.detail) || "Search failed.");
              }

              const results = payload.results || [];
              if (!results.length) {
                statusEl.textContent = "No users found matching that name.";
                return;
              }

              statusEl.textContent = `Found ${results.length} user(s) with Twilio lookup.`;

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Twilio Number</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Phone SID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Lookup Account</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Twilio Status</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                const uid = r.userid || "";
                const telephone = r.telephone || "—";
                const twilio = r.twilio_lookup || {};
                const twilioNumber = twilio.phone_number || "—";
                const twilioSid = twilio.sid || "—";
                const twilioAccount = twilio.lookup_account_name || "—";
                const twilioStatus = twilio.status || "—";

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px;">' + twilioNumber + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + twilioSid + '</td>';
                html += '<td style="padding:7px 10px;">' + twilioAccount + '</td>';
                html += '<td style="padding:7px 10px;">' + twilioStatus + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Twilio Direct Number Lookup Handler
        (function () {
          const form = document.getElementById("twilio-number-lookup-form");
          const statusEl = document.getElementById("twilio-number-lookup-status");
          const resultsEl = document.getElementById("twilio-number-lookup-results");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Looking up...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);

              const response = await fetch("/lookup/twilio-by-number", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.error) || "Lookup failed.");
              }

              const result = payload.result || {};
              const phoneNumber = payload.phone_number || "";

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left;">Property</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Value</th>';
              html += '</tr></thead><tbody>';

              const rows = [
                { label: "Phone Number", value: phoneNumber },
                { label: "Found", value: result.found ? "Yes" : "No" },
                { label: "Twilio Number", value: result.phone_number || "—" },
                { label: "Phone SID", value: result.sid || "—" },
                { label: "Lookup Account Name", value: result.lookup_account_name || "—" },
                { label: "Lookup Account SID", value: result.lookup_account_sid || "—" },
                { label: "Status", value: result.status || "—" },
              ];

              rows.forEach(function (row, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px; font-weight:bold;">' + row.label + '</td>';
                html += '<td style="padding:7px 10px;">' + row.value + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              statusEl.textContent = result.found ? "✓ Found in Twilio" : "✗ Not found in Twilio";
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Twilio SMS Hosting - AMIEWeb (SMS-only webhook updates)
        (function () {
          const form = document.getElementById("twilio-sms-host-form");
          const statusEl = document.getElementById("twilio-sms-host-status");
          const resultsEl = document.getElementById("twilio-sms-host-results");
          const verifyQueueEl = document.getElementById("twilio-sms-verify-queue");

          if (!form || !statusEl || !resultsEl) return;

          function normalizeForTranslationPattern(rawValue) {
            const digits = String(rawValue || "").replace(/\D/g, "");
            if (digits.length === 11 && digits.startsWith("1")) {
              return digits.slice(1);
            }
            return digits;
          }

          async function routeVerificationCall(profileKey, targetPattern) {
            const formData = new URLSearchParams({
              cucm_host: "__AUTH_CUCM_HOST__",
              cucm_user: "__AUTH_USER__",
              cucm_pass: "",
              profile_key: profileKey,
              target_pattern: targetPattern,
            });

            const response = await fetch("/translation-pattern/twilio-inbound-verification", {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: formData.toString(),
              credentials: "same-origin",
            });

            const payload = await response.json();
            if (!response.ok || !payload.ok) {
              throw new Error((payload && payload.error) || (payload && payload.detail) || "Verification route update failed.");
            }
            return payload;
          }

          async function markVerificationStatus(row, verificationStatus, notes) {
            try {
              const body = new URLSearchParams({
                friendly_name: row.friendly_name || "",
                normalized_number: row.normalized || "",
                verification_status: verificationStatus,
                notes: notes || "",
              });
              await fetch("/twilio/amieweb/verification/mark", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: body.toString(),
                credentials: "same-origin",
              });
            } catch (_err) {
              // Non-blocking for operator flow.
            }
          }

          function renderVerificationQueue(rows, loaModeText, loaRefText) {
            if (!verifyQueueEl) {
              return;
            }

            const queue = (rows || [])
              .map(function (row) {
                return {
                  input: row.input || "",
                  normalized: row.normalized || "",
                  friendly_name: row.friendly_name || "",
                  verification_code: row.verification_code || "",
                  sid: row.sid || "",
                  status: row.status || "",
                  ok: !!row.ok,
                  routed_profile: "",
                  verified: false,
                };
              })
              .filter(function (item) {
                return !!item.verification_code;
              });

            if (!queue.length) {
              verifyQueueEl.innerHTML = "";
              return;
            }

            let idx = 0;

            const render = function () {
              const current = queue[idx] || null;
              if (!current) {
                verifyQueueEl.innerHTML = '<div style="border:1px solid #c8dbee;border-radius:8px;background:#f8fbff;padding:12px;">All verification-code items are complete.</div>';
                return;
              }

              const completed = queue.filter(function (item) { return item.verified; }).length;
              const total = queue.length;
              const loaLine = loaModeText
                ? ('LOA Mode: <strong>' + loaModeText + '</strong>' + (loaRefText ? (' | Reference: <strong>' + loaRefText + '</strong>') : ''))
                : '';

              verifyQueueEl.innerHTML =
                '<div style="border:1px solid #c8dbee;border-radius:8px;background:#f8fbff;padding:12px;">'
                + '<h4 style="margin:0 0 8px 0;color:#12304a;">Twilio Verification Queue (One Number at a Time)</h4>'
                + '<p style="margin:0 0 8px 0;color:#355978;">Item ' + (idx + 1) + ' of ' + total + ' | Verified: ' + completed + '</p>'
                + (loaLine ? ('<p style="margin:0 0 8px 0;color:#355978;">' + loaLine + '</p>') : '')
                + '<p style="margin:0 0 6px 0;"><strong>Number:</strong> ' + (current.normalized || current.input || '') + '</p>'
                + '<p style="margin:0 0 8px 0;"><strong>Phone SID:</strong> <span style="font-family:Consolas,monospace;">' + (current.sid || '—') + '</span></p>'
                + '<div style="font-family:Consolas,monospace;font-size:22px;font-weight:700;color:#002f6c;background:#fff;border:1px solid #b7d0e6;border-radius:6px;padding:8px 10px;display:inline-block;">'
                + (current.verification_code || '—')
                + '</div>'
                + '<p style="margin:8px 0 10px 0;color:#355978;">Read this code, trigger the Twilio ownership call, answer on selected Jabber target, then key in this code.</p>'
                + '<div style="display:flex;flex-wrap:wrap;gap:8px;">'
                + '<button type="button" id="twilio-queue-route-phimane" style="background:#005eb8;color:#fff;border:none;border-radius:6px;padding:7px 10px;font-weight:700;cursor:pointer;">Route Call to Phimane</button>'
                + '<button type="button" id="twilio-queue-route-lauraa" style="background:#0f766e;color:#fff;border:none;border-radius:6px;padding:7px 10px;font-weight:700;cursor:pointer;">Route Call to LauraA</button>'
                + '<button type="button" id="twilio-queue-mark-next" style="background:#237741;color:#fff;border:none;border-radius:6px;padding:7px 10px;font-weight:700;cursor:pointer;">Mark Verified and Next</button>'
                + '<button type="button" id="twilio-queue-skip-next" style="background:#6b7280;color:#fff;border:none;border-radius:6px;padding:7px 10px;font-weight:700;cursor:pointer;">Skip to Next</button>'
                + '</div>'
                + '<p id="twilio-queue-status" style="margin:10px 0 0 0;color:#2c5c8a;min-height:18px;">Current route: '
                + (current.routed_profile ? current.routed_profile : 'Not set')
                + '</p>'
                + '</div>';

              const queueStatusEl = document.getElementById("twilio-queue-status");
              const targetPattern = normalizeForTranslationPattern(current.normalized || current.input || "");

              const bindRouteButton = function (buttonId, profileKey, label) {
                const btn = document.getElementById(buttonId);
                if (!btn) {
                  return;
                }
                btn.addEventListener("click", async function () {
                  if (!targetPattern) {
                    queueStatusEl.textContent = "Cannot route: target number is empty.";
                    return;
                  }
                  btn.disabled = true;
                  queueStatusEl.textContent = "Updating translation pattern route to " + label + "...";
                  try {
                    await routeVerificationCall(profileKey, targetPattern);
                    current.routed_profile = label;
                    queueStatusEl.textContent = "Route set to " + label + " for " + targetPattern + ".";
                  } catch (err) {
                    queueStatusEl.textContent = "Route update failed: " + ((err && err.message) || "Unknown error.");
                    btn.disabled = false;
                  }
                });
              };

              bindRouteButton("twilio-queue-route-phimane", "phimane", "Phimane");
              bindRouteButton("twilio-queue-route-lauraa", "lauraa", "LauraA");

              const markBtn = document.getElementById("twilio-queue-mark-next");
              if (markBtn) {
                markBtn.addEventListener("click", async function () {
                  current.verified = true;
                  await markVerificationStatus(current, "verified", "Marked verified in queue");
                  if (idx < queue.length - 1) {
                    idx += 1;
                    render();
                  } else {
                    verifyQueueEl.innerHTML = '<div style="border:1px solid #c8dbee;border-radius:8px;background:#eefbf2;color:#145c2e;padding:12px;font-weight:700;">Verification queue complete. All items marked verified.</div>';
                  }
                });
              }

              const skipBtn = document.getElementById("twilio-queue-skip-next");
              if (skipBtn) {
                skipBtn.addEventListener("click", async function () {
                  await markVerificationStatus(current, "pending", "Skipped in queue");
                  if (idx < queue.length - 1) {
                    idx += 1;
                    render();
                  } else {
                    queueStatusEl.textContent = "Already at last queue item.";
                  }
                });
              }
            };

            render();
          }

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Applying SMS hosting configuration...";
            resultsEl.innerHTML = "";
            if (verifyQueueEl) {
              verifyQueueEl.innerHTML = "";
            }

            try {
              const formData = new FormData(form);
              const response = await fetch("/twilio/amieweb/sms-host", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.error) || "SMS hosting update failed.");
              }

              const summary = payload.summary || {};
              const submitted = payload.submitted || {};
              const friendlyNote = (submitted.friendly_name_mode === "custom")
                ? (`FriendlyName: ${submitted.friendly_name || ""}`)
                : (`FriendlyName auto-seed: ${submitted.friendly_name_auto_seed || ""}`);
              const loaNote = submitted.loa_recipient_email
                ? (`LOA contact: ${submitted.loa_recipient_name || ""} <${submitted.loa_recipient_email}>`)
                : "LOA contact: not set";
              const loaModeNote = submitted.loa_mode === "per_number" ? "LOA mode: Per Number" : "LOA mode: Single Batch";
              const subaccountNote = `Subaccount: ${(submitted.subaccount_name || "")}${submitted.subaccount_sid ? ` (${submitted.subaccount_sid})` : ""}`;
              statusEl.textContent = `Requested: ${summary.requested || 0} | Updated: ${summary.updated || 0} | Failed: ${summary.failed || 0} | ${friendlyNote} | ${subaccountNote} | ${loaNote} | ${loaModeNote}`;

              const rows = payload.results || [];
              if (!rows.length) {
                resultsEl.innerHTML = "";
                return;
              }

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Input</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Normalized</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Phone SID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Friendly Name</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Verification Code</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Result</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Status</th>';
              html += '</tr></thead><tbody>';

              rows.forEach(function (row, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const result = row.action || (row.ok ? "Updated" : "Failed");
                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + (row.input || "") + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (row.normalized || "") + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (row.sid || "—") + '</td>';
                html += '<td style="padding:7px 10px;">' + (row.friendly_name || "—") + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace; font-weight:700; color:#002f6c;">' + (row.verification_code || "—") + '</td>';
                html += '<td style="padding:7px 10px; font-weight:700; color:' + (row.ok ? '#145c2e' : '#a01818') + ';">' + result + '</td>';
                html += '<td style="padding:7px 10px;">' + (row.status || "") + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;

              renderVerificationQueue(rows, submitted.loa_mode === "per_number" ? "Per Number" : "Single LOA for Batch", submitted.loa_batch_reference || "");
            } catch (err) {
              statusEl.textContent = "Update failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Recent Friendly Name status lookup for long-running completion tracking.
        (function () {
          const form = document.getElementById("twilio-friendly-status-form");
          const statusEl = document.getElementById("twilio-friendly-status-status");
          const resultsEl = document.getElementById("twilio-friendly-status-results");
          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Loading recent friendly-name status...";
            resultsEl.innerHTML = "";

            try {
              const fd = new FormData(form);
              const name = String(fd.get("friendly_name") || "").trim();
              const query = new URLSearchParams({
                friendly_name: name,
                limit: "100",
              });
              const response = await fetch("/twilio/amieweb/friendly-name-status?" + query.toString(), {
                method: "GET",
                credentials: "same-origin",
              });
              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.error) || "Status lookup failed.");
              }

              const rows = payload.rows || [];
              statusEl.textContent = `Status rows: ${rows.length}`;
              if (!rows.length) {
                resultsEl.innerHTML = "";
                return;
              }

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left;">Timestamp</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Submitter</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Friendly Name</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Number</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Verification</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Result</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Messaging Service</th>';
              html += '</tr></thead><tbody>';

              rows.forEach(function (row, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + (row.timestamp || "") + '</td>';
                html += '<td style="padding:7px 10px;">' + (row.submitter || "") + '</td>';
                html += '<td style="padding:7px 10px;">' + (row.session_friendly_name || "") + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + (row.normalized_number || row.input_number || "") + '</td>';
                html += '<td style="padding:7px 10px;">' + (row.verification_status || "") + '</td>';
                html += '<td style="padding:7px 10px;">' + (row.result_status || row.result_action || "") + '</td>';
                html += '<td style="padding:7px 10px;">' + (row.messaging_service_status || "") + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Status lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Twilio Lookup Form Handler - Salesforce Enterprise Org Prod
        (function () {
          const form = document.getElementById("twilio-lookup-sfdc-search-form");
          const statusEl = document.getElementById("twilio-lookup-sfdc-search-status");
          const resultsEl = document.getElementById("twilio-lookup-sfdc-search-results");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Searching...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              formData.append("include_twilio_lookup", "1");
              formData.append("twilio_lookup_account", "salesforce");
              const response = await fetch("/lookup/person", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.detail) || "Search failed.");
              }

              const results = payload.results || [];
              if (!results.length) {
                statusEl.textContent = "No users found matching that name.";
                return;
              }

              statusEl.textContent = `Found ${results.length} user(s) with Twilio lookup.`;

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Twilio Number</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Phone SID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Twilio Status</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                const uid = r.userid || "";
                const telephone = r.telephone || "—";
                const twilio = r.twilio_lookup || {};
                const twilioNumber = twilio.phone_number || "—";
                const twilioSid = twilio.sid || "—";
                const twilioStatus = twilio.status || "—";

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px;">' + twilioNumber + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + twilioSid + '</td>';
                html += '<td style="padding:7px 10px;">' + twilioStatus + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Twilio Direct Number Lookup Handler - Salesforce
        (function () {
          const form = document.getElementById("twilio-number-lookup-sfdc-form");
          const statusEl = document.getElementById("twilio-number-lookup-sfdc-status");
          const resultsEl = document.getElementById("twilio-number-lookup-sfdc-results");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Looking up...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);

              const response = await fetch("/lookup/twilio-by-number-sfdc", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.error) || "Lookup failed.");
              }

              const result = payload.result || {};
              const phoneNumber = payload.phone_number || "";

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left;">Property</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Value</th>';
              html += '</tr></thead><tbody>';

              const rows = [
                { label: "Phone Number", value: phoneNumber },
                { label: "Found", value: result.found ? "Yes" : "No" },
                { label: "Twilio Number", value: result.phone_number || "—" },
                { label: "Phone SID", value: result.sid || "—" },
                { label: "Status", value: result.status || "—" },
              ];

              rows.forEach(function (row, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px; font-weight:bold;">' + row.label + '</td>';
                html += '<td style="padding:7px 10px;">' + row.value + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              statusEl.textContent = result.found ? "✓ Found in Twilio (Salesforce)" : "✗ Not found in Twilio (Salesforce)";
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Aerialink SMS-AMIEClassic Lookup Handler
        (function () {
          const form = document.getElementById("aerialink-amieclassic-search-form");
          const statusEl = document.getElementById("aerialink-amieclassic-search-status");
          const resultsEl = document.getElementById("aerialink-amieclassic-search-results");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Searching...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);
              formData.append("include_aerialink_lookup", "1");

              const response = await fetch("/lookup/person", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.detail) || "Search failed.");
              }

              const results = payload.results || [];
              if (!results.length) {
                statusEl.textContent = "No users found matching that name.";
                return;
              }

              statusEl.textContent = `Found ${results.length} user(s) with Aerialink lookup.`;

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Name</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">User ID</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Telephone</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Requested Number</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Matched Account Code</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Provisioned</th>';
              html += '<th style="padding:8px 10px; text-align:left; white-space:nowrap;">Aerialink Status</th>';
              html += '</tr></thead><tbody>';

              results.forEach(function (r, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                const name = r.display_name || ((r.first_name || "") + " " + (r.last_name || "")).trim() || r.userid;
                const uid = r.userid || "";
                const telephone = r.telephone || "—";
                const aerialink = r.aerialink_lookup || {};
                const requested = aerialink.requested_number || "—";
                const matched = aerialink.matched_number || "—";
                const provisioned = aerialink.provisioned ? "Yes" : "No";
                const lookupStatus = aerialink.status || "—";

                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px;">' + name + '</td>';
                html += '<td style="padding:7px 10px; font-family:Consolas,monospace;">' + uid + '</td>';
                html += '<td style="padding:7px 10px;">' + telephone + '</td>';
                html += '<td style="padding:7px 10px;">' + requested + '</td>';
                html += '<td style="padding:7px 10px;">' + matched + '</td>';
                html += '<td style="padding:7px 10px;">' + provisioned + '</td>';
                html += '<td style="padding:7px 10px;">' + lookupStatus + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Search failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();

        // Aerialink Direct Number Lookup Handler
        (function () {
          const form = document.getElementById("aerialink-number-lookup-form");
          const statusEl = document.getElementById("aerialink-number-lookup-status");
          const resultsEl = document.getElementById("aerialink-number-lookup-results");

          if (!form || !statusEl || !resultsEl) return;

          form.addEventListener("submit", async function (event) {
            event.preventDefault();
            statusEl.textContent = "Looking up...";
            resultsEl.innerHTML = "";

            try {
              const formData = new FormData(form);

              const response = await fetch("/lookup/aerialink-by-number", {
                method: "POST",
                body: formData,
                credentials: "same-origin",
              });

              const payload = await response.json();
              if (!response.ok || !payload.ok) {
                throw new Error((payload && payload.error) || "Lookup failed.");
              }

              const result = payload.result || {};
              const phoneNumber = payload.phone_number || "";

              let html = '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
              html += '<thead><tr style="background:#005eb8; color:#fff;">';
              html += '<th style="padding:8px 10px; text-align:left;">Property</th>';
              html += '<th style="padding:8px 10px; text-align:left;">Value</th>';
              html += '</tr></thead><tbody>';

              const rows = [
                { label: "Phone Number", value: phoneNumber },
                { label: "Enabled", value: result.enabled ? "Yes" : "No" },
                { label: "Found", value: result.found ? "Yes" : "No" },
                { label: "Provisioned", value: result.provisioned ? "Yes" : "No" },
                { label: "Requested Number", value: result.requested_number || "—" },
                { label: "Matched Number", value: result.matched_number || "—" },
                { label: "Status", value: result.status || "—" },
              ];

              rows.forEach(function (row, i) {
                const bg = i % 2 === 0 ? "#f7fbff" : "#ffffff";
                html += '<tr style="background:' + bg + '; border-bottom:1px solid #c8dbee;">';
                html += '<td style="padding:7px 10px; font-weight:bold;">' + row.label + '</td>';
                html += '<td style="padding:7px 10px;">' + row.value + '</td>';
                html += '</tr>';
              });

              html += '</tbody></table>';
              statusEl.textContent = result.provisioned ? "✓ Provisioned in Aerialink" : "✗ Not provisioned in Aerialink";
              resultsEl.innerHTML = html;
            } catch (err) {
              statusEl.textContent = "Lookup failed: " + ((err && err.message) || "Unknown error.");
            }
          });
        })();
      })();
    </script>

      </section>
    </div>
    </main>
  </body>
</html>
""".replace("__SMS_LOOK_MENU__", sms_look_menu_html).replace("__SMS_LOOK_PANEL__", sms_look_panel_html).replace("__SMS_EXPERIMENTAL_MENU__", sms_experimental_menu_html).replace("__SMS_EXPERIMENTAL_PANEL__", sms_experimental_panel_html).replace("__TWILIO_LOOKUP_ACTIVE_CLASS__", twilio_lookup_btn_active_class).replace("__AUTH_USER__", auth_user).replace("__AUTH_CUCM_HOST__", escape(auth_cucm_host)).replace("__ENV_TEXT__", escape(env_text)).replace("__ENV_CLASS__", env_css_class).replace("__HAS_CACHED_CUCM_PASS__", "true" if has_cached_cucm_pass else "false").replace("__CREDENTIAL_EXPIRES_AT_MS__", str(credential_expires_at_ms)).replace("__DEFAULT_TWILIO_SMS_URL__", escape(TWILIO_AMIEWEB_DEFAULT_SMS_URL)).replace("__DEFAULT_TWILIO_LOA_RECIPIENT_NAME__", escape(default_twilio_loa_recipient_name)).replace("__DEFAULT_TWILIO_LOA_RECIPIENT_EMAIL__", escape(default_twilio_loa_recipient_email)).replace("__DEFAULT_TWILIO_LOA_RECIPIENT_PHONE__", escape(default_twilio_loa_recipient_phone))

  return HTMLResponse(
    content=html,
    headers={
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "Pragma": "no-cache",
      "Expires": "0",
    },
  )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
  """Admin settings page for configuring phone prefixes and Twilio LOA defaults."""
  session = _get_auth_session(request) or {}
  session_username = str(session.get("username", ""))
  if not _is_admin_user(session_username):
    return HTMLResponse(
      content="<h3>403 Forbidden</h3><p>You are not authorized to access Settings.</p>",
      status_code=403,
    )
  
  settings = _load_settings()
  auth_user = escape(session_username)
  
  html = f"""
<html>
  <head>
    <title>DN Prefix Settings - Voice Operations Portal</title>
    <style>
      :root {{
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-text: #12304a;
        --amn-text-soft: #4e6a84;
        --amn-border: #c8dbee;
      }}
      body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: linear-gradient(135deg, #f6fbff 0%, #eaf4ff 100%);
        margin: 0;
        padding: 20px;
        color: var(--amn-text);
      }}
      .container {{
        max-width: 600px;
        margin: 0 auto;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        overflow: hidden;
      }}
      .header {{
        background: linear-gradient(135deg, var(--amn-blue) 0%, var(--amn-navy) 100%);
        color: white;
        padding: 30px;
        text-align: center;
      }}
      .header h1 {{
        margin: 0;
        font-size: 28px;
      }}
      .header p {{
        margin: 8px 0 0 0;
        opacity: 0.95;
        font-size: 14px;
      }}
      .content {{
        padding: 30px;
      }}
      .form-group {{
        margin-bottom: 24px;
      }}
      label {{
        display: block;
        font-weight: 600;
        margin-bottom: 8px;
        color: var(--amn-text);
        font-size: 14px;
      }}
      input[type="text"] {{
        width: 100%;
        padding: 10px 12px;
        border: 1px solid var(--amn-border);
        border-radius: 4px;
        font-size: 14px;
        box-sizing: border-box;
      }}
      input[type="text"]:focus {{
        outline: none;
        border-color: var(--amn-blue);
        box-shadow: 0 0 0 3px rgba(0,94,184,0.1);
      }}
      .help-text {{
        font-size: 12px;
        color: var(--amn-text-soft);
        margin-top: 4px;
      }}
      .button-group {{
        display: flex;
        gap: 12px;
        margin-top: 30px;
      }}
      button {{
        flex: 1;
        padding: 12px;
        border: none;
        border-radius: 4px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
      }}
      .btn-save {{
        background: var(--amn-blue);
        color: white;
      }}
      .btn-save:hover {{
        background: var(--amn-navy);
      }}
      .btn-cancel {{
        background: #e8ecf1;
        color: var(--amn-text);
      }}
      .btn-cancel:hover {{
        background: #d4dce5;
      }}
      .alert {{
        padding: 12px;
        border-radius: 4px;
        margin-bottom: 20px;
        font-size: 14px;
      }}
      .alert-success {{
        background: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
      }}
      .alert-error {{
        background: #f8d7da;
        color: #721c24;
        border: 1px solid #f5c6cb;
      }}
      .footer {{
        padding: 20px 30px;
        background: #f8fafc;
        border-top: 1px solid var(--amn-border);
        font-size: 12px;
        color: var(--amn-text-soft);
        text-align: center;
      }}
      a {{
        color: var(--amn-blue);
        text-decoration: none;
      }}
      a:hover {{
        text-decoration: underline;
      }}
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h1>DN Prefix Settings</h1>
        <p>Manage phone number prefixes and Twilio LOA defaults</p>
      </div>
      
      <div class="content">
        <div id="message"></div>
        
        <form id="settingsForm">
          <div class="form-group">
            <label for="general_fte_prefix">General FTE Prefix</label>
            <input type="text" id="general_fte_prefix" name="general_fte_prefix" value="{escape(settings.get('general_fte_prefix', '945'))}" maxlength="10" required>
            <div class="help-text">Used when building General FTE Jabber phones</div>
          </div>
          
          <div class="form-group">
            <label for="strike_prefix">Strike Prefix</label>
            <input type="text" id="strike_prefix" name="strike_prefix" value="{escape(settings.get('strike_prefix', '817'))}" maxlength="10" required>
            <div class="help-text">Used when building Strike Jabber phones</div>
          </div>
          
          <div class="form-group">
            <label for="recruiter_prefix">Recruiter Prefix</label>
            <input type="text" id="recruiter_prefix" name="recruiter_prefix" value="{escape(settings.get('recruiter_prefix', '469'))}" maxlength="10" required>
            <div class="help-text">Used when building Recruiter Jabber phones</div>
          </div>

          <div class="form-group">
            <label for="twilio_loa_recipient_name">Twilio LOA Recipient Name</label>
            <input type="text" id="twilio_loa_recipient_name" name="twilio_loa_recipient_name" value="{escape(settings.get('twilio_loa_recipient_name', 'Laura Alvarez'))}" maxlength="120">
            <div class="help-text">Default person for LOA handoff during Twilio hosted-number onboarding</div>
          </div>

          <div class="form-group">
            <label for="twilio_loa_recipient_email">Twilio LOA Recipient Email</label>
            <input type="text" id="twilio_loa_recipient_email" name="twilio_loa_recipient_email" value="{escape(settings.get('twilio_loa_recipient_email', 'laura.alvarez@amnhealthare.com'))}" maxlength="254">
            <div class="help-text">Default LOA email target used by Twilio SMS Hosting form</div>
          </div>

          <div class="form-group">
            <label for="twilio_loa_recipient_phone">Twilio LOA Recipient Phone</label>
            <input type="text" id="twilio_loa_recipient_phone" name="twilio_loa_recipient_phone" value="{escape(settings.get('twilio_loa_recipient_phone', '+18583503289'))}" maxlength="32">
            <div class="help-text">Default LOA phone for operator reference</div>
          </div>
          
          <div class="button-group">
            <button type="submit" class="btn-save">Save Changes</button>
            <button type="button" class="btn-cancel" onclick="window.location.href='/menu-admin'">Cancel</button>
          </div>
        </form>
      </div>
      
      <div class="footer">
        Logged in as: <strong>{auth_user}</strong> | 
        <a href="/logout">Logout</a>
      </div>
    </div>
    
    <script>
      document.getElementById('settingsForm').addEventListener('submit', async (e) => {{
        e.preventDefault();
        const messageEl = document.getElementById('message');
        
        const formData = {{
          general_fte_prefix: document.getElementById('general_fte_prefix').value.trim(),
          strike_prefix: document.getElementById('strike_prefix').value.trim(),
          recruiter_prefix: document.getElementById('recruiter_prefix').value.trim(),
          twilio_loa_recipient_name: document.getElementById('twilio_loa_recipient_name').value.trim(),
          twilio_loa_recipient_email: document.getElementById('twilio_loa_recipient_email').value.trim(),
          twilio_loa_recipient_phone: document.getElementById('twilio_loa_recipient_phone').value.trim(),
        }};
        
        if (!formData.general_fte_prefix || !formData.strike_prefix || !formData.recruiter_prefix) {{
          messageEl.innerHTML = '<div class="alert alert-error">All fields are required.</div>';
          return;
        }}
        
        try {{
          const resp = await fetch('/api/settings', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(formData),
            credentials: 'same-origin',
          }});
          
          const result = await resp.json();
          
          if (result.ok) {{
            messageEl.innerHTML = '<div class="alert alert-success">Settings saved successfully!</div>';
            setTimeout(() => window.location.href='/menu-admin', 1500);
          }} else {{
            messageEl.innerHTML = '<div class="alert alert-error">Error: ' + escape(result.error || 'Unknown error') + '</div>';
          }}
        }} catch (err) {{
          messageEl.innerHTML = '<div class="alert alert-error">Network error: ' + escape(err.message) + '</div>';
        }}
      }});
    </script>
  </body>
</html>
"""
  
  return HTMLResponse(content=html)


@app.get("/api/settings")
def get_settings_api(request: Request):
  """Get current DN prefix settings."""
  session = _get_auth_session(request)
  if not session:
    return JSONResponse({"ok": False, "error": "Authentication required"}, status_code=401)
  
  if not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)
  
  settings = _load_settings()
  return JSONResponse({"ok": True, "settings": settings})


@app.post("/api/settings")
def update_settings_api(request: Request, body: dict = None):
  """Update DN prefix settings and Twilio LOA defaults."""
  session = _get_auth_session(request)
  if not session:
    return JSONResponse({"ok": False, "error": "Authentication required"}, status_code=401)
  
  if not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)
  
  try:
    import asyncio
    loop = asyncio.new_event_loop()
    
    async def get_body():
      return await request.json()
    
    try:
      body = loop.run_until_complete(get_body())
    finally:
      loop.close()
    
    if not body:
      return JSONResponse({"ok": False, "error": "No data provided"}, status_code=400)
    
    # Validate and extract fields
    general_fte_prefix = (body.get("general_fte_prefix", "") or "").strip()
    strike_prefix = (body.get("strike_prefix", "") or "").strip()
    recruiter_prefix = (body.get("recruiter_prefix", "") or "").strip()
    twilio_loa_recipient_name = (body.get("twilio_loa_recipient_name", "") or "").strip()
    twilio_loa_recipient_email = (body.get("twilio_loa_recipient_email", "") or "").strip()
    twilio_loa_recipient_phone = (body.get("twilio_loa_recipient_phone", "") or "").strip()
    
    if not general_fte_prefix or not strike_prefix or not recruiter_prefix:
      return JSONResponse({"ok": False, "error": "All fields are required"}, status_code=400)
    
    # Validate that all are numeric
    if not (general_fte_prefix.isdigit() and strike_prefix.isdigit() and recruiter_prefix.isdigit()):
      return JSONResponse({"ok": False, "error": "All prefixes must be numeric"}, status_code=400)
    
    new_settings = {
      "general_fte_prefix": general_fte_prefix,
      "strike_prefix": strike_prefix,
      "recruiter_prefix": recruiter_prefix,
      "twilio_loa_recipient_name": twilio_loa_recipient_name,
      "twilio_loa_recipient_email": twilio_loa_recipient_email,
      "twilio_loa_recipient_phone": twilio_loa_recipient_phone,
    }
    
    if _save_settings(new_settings):
      return JSONResponse({"ok": True, "message": "Settings saved successfully"})
    else:
      return JSONResponse({"ok": False, "error": "Failed to save settings"}, status_code=500)
  
  except Exception as e:
    return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


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


@app.get("/download/verasmart-queue-template")
def download_verasmart_queue_template():
  template_csv = "record_key,target_change,note\nEMP001,Update Cost Center to 12345,LAB test row\nEMP002,Disable mobile allowance,LAB test row\n"
  return Response(
    template_csv.encode("utf-8"),
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="verasmart_queue_template.csv"'}
  )


@app.get("/download/strike-mask-translation-template")
def download_strike_mask_translation_template():
  template_csv = (
    "pattern,description,notes\n"
    "9452190000,Strike Mask - 9452190000 Available,Example available row\n"
    "9552190001,Strike Mask - 9552190001 Available,Example alternate range\n"
  )
  return Response(
    template_csv.encode("utf-8"),
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="strike_mask_translation_upload_template.csv"'}
  )


@app.post("/strike-mask-translation/upload")
def strike_mask_translation_upload(
  request: Request,
  cucm_host: str = Form(""),
  cucm_user: str = Form(""),
  cucm_pass: str = Form(""),
  csv_file: UploadFile = File(...),
):
  try:
    _require_admin_session(request)
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user, cucm_pass=cucm_pass)

    csv_content = csv_file.file.read().decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(csv_content))
    
    rows_to_create = []
    for raw_row in reader:
      if not raw_row:
        continue
      row = {k.lower().strip(): (v or "").strip() for k, v in (raw_row or {}).items()}
      pattern = row.get("pattern", "").strip()
      description = row.get("description", "").strip()
      notes = row.get("notes", "").strip()
      
      if pattern and description:
        rows_to_create.append({
          "pattern": pattern,
          "description": description,
          "notes": notes,
          "status": "",
          "error": "",
        })
    
    if not rows_to_create:
      raise RuntimeError("No valid rows found in CSV (pattern and description required)")
    
    session_obj = requests.Session()
    session_obj.verify = False
    session_obj.auth = HTTPBasicAuth(cucm_user, cucm_pass)
    
    output_rows = []
    output_rows.append(["pattern", "description", "notes", "status", "error"])
    
    for row in rows_to_create:
      pattern = row["pattern"]
      description = row["description"]
      notes = row["notes"]
      
      try:
        soap_xml = _build_add_translation_pattern_soap(
          pattern=pattern,
          description=description,
          route_partition=STRIKE_MASK_ROUTE_PARTITION,
          called_party_transform_mask=STRIKE_MASK_AVAILABLE_TRANSFORM_MASK,
        )
        
        response = session_obj.post(
          f"https://{cucm_host}:8443/axl/",
          data=soap_xml.encode("utf-8"),
          headers={"Content-Type": "text/xml"},
          timeout=60,
        )
        
        # Check for SOAP fault in response (even on HTTP 200)
        if response.status_code != 200 or "Fault" in response.text:
          error_msg = _extract_soap_error(response.text)
          output_rows.append([pattern, description, notes, "Failed", error_msg])
        else:
          output_rows.append([pattern, description, notes, "Success", ""])
      except Exception as e:
        output_rows.append([pattern, description, notes, "Failed", str(e)[:200]])
    
    csv_output = io.StringIO()
    writer = csv.writer(csv_output)
    writer.writerows(output_rows)
    csv_bytes = csv_output.getvalue().encode("utf-8")

    success_count = 0
    failed_count = 0
    for result_row in output_rows[1:]:
      row_status = (result_row[3] if len(result_row) > 3 else "").strip().lower()
      if row_status == "success":
        success_count += 1
      elif row_status == "failed":
        failed_count += 1
    
    job_result = _prepare_job_output(csv_bytes, "strike_mask_translation_create_results.csv")
    job_result["summary"] = {
      "total_rows": len(rows_to_create),
      "success_count": success_count,
      "failed_count": failed_count,
    }
    
    csv_name = csv_file.filename or "uploaded.csv"
    _append_audit_event(
      action="strike_mask_translation_upload",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=csv_name,
      output_filename="strike_mask_translation_create_results.csv",
      inline_mode=False,
    )
    
    return JSONResponse(job_result)
  except RuntimeError as re:
    return JSONResponse({"detail": str(re)}, status_code=400)
  except Exception as e:
    return JSONResponse({"detail": f"Error: {str(e)[:400]}"}, status_code=500)


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
      "git_commit": _git_commit_short(),
      "feature_flags": {
        "preview_lab_only_default": PREVIEW_FEATURES_LAB_ONLY_DEFAULT,
        "sms_experimental_menu_enabled": SMS_EXPERIMENTAL_MENU_ENABLED,
        "sms_experimental_menu_lab_only": SMS_EXPERIMENTAL_MENU_LAB_ONLY,
        "integration_preflight_required": INTEGRATION_PREFLIGHT_REQUIRED,
      },
    }
  )


@app.get("/ops/integrations/feasibility")
def integrations_feasibility(request: Request, force_refresh: bool = False):
  session, username = _require_admin_session(request)
  cucm_host = str(session.get("cucm_host", "") or "")
  result = {
    "ok": True,
    "operator": username,
    "environment": "LAB" if _is_lab_environment(cucm_host) else "PROD",
    "checked_at": datetime.datetime.now().strftime(AUDIT_TIMESTAMP_FORMAT),
    "integrations": {
      "aerialink": _check_aerialink_feasibility(force_refresh=force_refresh),
    },
  }
  return JSONResponse(result)


@app.get("/ops/parity-report")
def ops_parity_report(request: Request):
  session, username = _require_admin_session(request)
  cucm_host = str(session.get("cucm_host", "") or "")
  env_label = "LAB" if _is_lab_environment(cucm_host) else "PROD"
  return JSONResponse(
    {
      "ok": True,
      "operator": username,
      "timestamp": datetime.datetime.now().strftime(AUDIT_TIMESTAMP_FORMAT),
      "git_commit": _git_commit_short(),
      "runtime_environment": env_label,
      "resolved_cucm_host": cucm_host,
      "flags": {
        "sms_number_lookup_enabled": SMS_NUMBER_LOOKUP_ENABLED,
        "twilio_hosted_numbers_active": TWILIO_HOSTED_NUMBERS_ACTIVE,
        "preview_lab_only_default": PREVIEW_FEATURES_LAB_ONLY_DEFAULT,
        "sms_experimental_menu_enabled": SMS_EXPERIMENTAL_MENU_ENABLED,
        "sms_experimental_menu_lab_only": SMS_EXPERIMENTAL_MENU_LAB_ONLY,
        "integration_preflight_required": INTEGRATION_PREFLIGHT_REQUIRED,
      },
      "integration_preflight": {
        "aerialink": _check_aerialink_feasibility(force_refresh=False),
      },
    }
  )


@app.get("/download/job-output/{job_id}")
def download_job_output(job_id: str):
  job_output = JOB_OUTPUTS.get(job_id)
  if not job_output:
    return Response("Job output not found.", media_type="text/plain", status_code=404)

  return Response(
    job_output["data"],
    media_type=str(job_output.get("media_type", "text/csv") or "text/csv"),
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


@app.get("/audit-trail", response_class=HTMLResponse)
def audit_trail_page():
  rows = _load_audit_rows(limit=100)
  action_counts = Counter((row.get("action") or "").strip() or "unknown" for row in rows)
  total_rows = len(rows)
  latest_timestamp = rows[0].get("timestamp", "No activity recorded yet") if rows else "No activity recorded yet"

  summary_cards = "".join(
    f"""
    <div class=\"history-card\">
      <span class=\"history-label\">{escape(action)}</span>
      <strong>{count}</strong>
    </div>
    """
    for action, count in action_counts.most_common(6)
  ) or '<div class="history-card"><span class="history-label">No actions logged yet</span><strong>0</strong></div>'

  table_rows = []
  for row in rows:
    target_text = (row.get("account") or row.get("target") or "")
    extension_text = (row.get("extension_added") or row.get("extension_deleted") or "")
    table_rows.append(
      "<tr>"
      f"<td>{escape(row.get('timestamp', ''))}</td>"
      f"<td>{escape(row.get('action', ''))}</td>"
      f"<td>{escape(row.get('operator', ''))}</td>"
      f"<td>{escape(target_text)}</td>"
      f"<td>{escape(extension_text)}</td>"
      f"<td>{escape(row.get('output_filename', ''))}</td>"
      f"<td>{escape(row.get('inline_mode', ''))}</td>"
      "</tr>"
    )
  history_rows_html = "".join(table_rows) if table_rows else "<tr><td colspan='7' style='padding:12px;'>No audit activity recorded yet.</td></tr>"

  html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Action History</title>
    <style>
      :root {{
        --amn-blue: #005eb8;
        --amn-navy: #002f6c;
        --amn-sky: #eaf4ff;
        --amn-text: #12304a;
        --amn-border: #c8dbee;
      }}
      body {{ margin: 0; font-family: Segoe UI, Tahoma, Arial, sans-serif; background: linear-gradient(180deg, #f7fbff 0%, #edf5fc 100%); color: var(--amn-text); }}
      .topbar {{ display:flex; align-items:center; gap:12px; padding:14px 24px; background: linear-gradient(90deg, var(--amn-navy), var(--amn-blue)); color:#fff; box-shadow:0 2px 12px rgba(0,47,108,.25); }}
      .content {{ max-width: 1380px; margin: 22px auto; padding: 0 18px 30px; }}
      .panel {{ background:#fff; border:1px solid var(--amn-border); border-radius:14px; padding:18px; box-shadow:0 8px 20px rgba(0,47,108,.08); }}
      .meta-grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:10px; margin:14px 0 18px; }}
      .history-card {{ border:1px solid var(--amn-border); border-radius:12px; background:var(--amn-sky); padding:12px 14px; }}
      .history-card strong {{ display:block; font-size:24px; color:var(--amn-navy); margin-top:4px; }}
      .history-label {{ display:block; font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:#5d7690; }}
      .toolbar {{ display:flex; flex-wrap:wrap; gap:10px; margin: 14px 0 18px; }}
      .toolbar a {{ color:#fff; background:var(--amn-blue); padding:10px 14px; border-radius:8px; text-decoration:none; font-weight:700; }}
      .toolbar a.secondary {{ background:#385977; }}
      .toolbar button {{ color:#fff; background:#237741; padding:10px 14px; border-radius:8px; border:none; font-weight:700; cursor:pointer; }}
      .table-wrap {{ overflow-x:auto; border:1px solid var(--amn-border); border-radius:12px; }}
      table {{ width:100%; border-collapse:collapse; font-size:13px; }}
      thead th {{ position:sticky; top:0; background:var(--amn-navy); color:#fff; text-align:left; padding:10px 12px; white-space:nowrap; }}
      tbody td {{ padding:8px 12px; border-top:1px solid #dce8f2; vertical-align:top; }}
      tbody tr:nth-child(even) {{ background:#f8fbff; }}
      .muted {{ color:#5d7690; }}
    </style>
  </head>
  <body>
    <header class="topbar">
      <span class="brand-fallback">AMN Healthcare</span>
      <strong>Voice Operations Portal</strong>
    </header>
    <main class="content">
      <section class="panel">
        <h2>Action History</h2>
        <p class="muted">Recent logged portal actions from the audit trail. Showing the latest {total_rows} record(s).</p>
        <div class="meta-grid">
          <div class="history-card"><span class="history-label">Records Shown</span><strong>{total_rows}</strong></div>
          <div class="history-card"><span class="history-label">Latest Activity</span><strong style="font-size:16px; line-height:1.3;">{escape(latest_timestamp)}</strong></div>
          <div class="history-card"><span class="history-label">Unique Actions</span><strong>{len(action_counts)}</strong></div>
        </div>
        <div class="toolbar">
          <a href="/download/audit-trail">Download Audit CSV</a>
          <button type="button" id="email-audit-log-btn">Email Audit CSV</button>
          <a class="secondary" href="/audit-trail/stats">View Audit Stats JSON</a>
          <a class="secondary" href="/menu">Back to Main Menu</a>
        </div>
        <p id="email-audit-log-status" class="muted" style="min-height:18px; margin:-8px 0 12px;">Use Email Audit CSV to send the current audit trail attachment to your admin email.</p>
        <div class="meta-grid">
          {summary_cards}
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Operator</th>
                <th>Target / Account</th>
                <th>Extensions</th>
                <th>Output</th>
                <th>Inline</th>
              </tr>
            </thead>
            <tbody>
              {history_rows_html}
            </tbody>
          </table>
        </div>
      </section>
    </main>
    <script>
      (function () {{
        const btn = document.getElementById("email-audit-log-btn");
        const statusEl = document.getElementById("email-audit-log-status");
        if (!btn || !statusEl) return;

        btn.addEventListener("click", async function () {{
          const originalLabel = btn.textContent;
          btn.disabled = true;
          btn.textContent = "Sending...";
          statusEl.textContent = "Sending audit log email...";

          try {{
            const fd = new FormData();
            const response = await fetch("/send/audit-trail-email", {{
              method: "POST",
              body: fd,
              credentials: "same-origin",
              headers: {{ "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" }},
            }});
            const payload = await response.json();
            if (!response.ok || !payload.ok) {{
              throw new Error((payload && payload.detail) || "Failed to send audit email.");
            }}
            statusEl.textContent = "Sent: " + (payload.detail || "Audit log emailed.");
            btn.textContent = "Sent";
          }} catch (err) {{
            statusEl.textContent = "Failed: " + ((err && err.message) || "Unknown error.");
            btn.textContent = originalLabel;
            btn.disabled = false;
          }}
        }});
      }})();
    </script>
  </body>
</html>
"""
  return HTMLResponse(html)


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
    return _render_job_result("Add Directory Numbers", log_csv, filename, back_url="/page2")


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
    return _render_job_result("Export Directory Numbers", data, filename, back_url="/page2")


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
    return _render_job_result("Export End Users", data, filename, back_url="/page2")


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

    build_ready_for_email = _csv_has_success_step(data, {"Add Phone", "Update User", "Unity Voicemail"})
    if build_ready_for_email:
      notify_status, notify_details = _send_csf_jabber_ready_email_if_created(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=clean_target_user,
        added_dn=added_dn,
        new_build=True,
      )
    else:
      notify_status, notify_details = (
        "Skipped",
        "Build did not complete Add Phone + Update User + Unity Voicemail successfully; email not sent",
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

    rebuild_ready_for_email = _csv_has_success_step(data, {"Add Phone", "Update User", "Unity Voicemail"})
    if rebuild_ready_for_email:
      notify_status, notify_details = _send_csf_jabber_ready_email_if_created(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=clean_target_user,
        added_dn=added_dn,
      )
    else:
      notify_status, notify_details = (
        "Skipped",
        "Rebuild did not complete Add Phone + Update User + Unity Voicemail successfully; email not sent",
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
    try:
      cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
      _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
      clean_pattern = (pattern or "").strip()
      if not clean_pattern:
          raise RuntimeError("Extension pattern is required.")
      result = lookup_extension_owner(cucm_host, cucm_user, cucm_pass, clean_pattern)
      return JSONResponse({"ok": True, **result})
    except RuntimeError:
      raise
    except Exception as exc:
      raise RuntimeError(f"Extension lookup failed: {exc}") from exc


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


@app.post("/translation-pattern/twilio-inbound-verification")
def twilio_inbound_verification_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    profile_key: str = Form("phimane"),
    target_pattern: str = Form(""),
    restore_default: str = Form("0"),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    profile = _get_twilio_inbound_verification_profile(profile_key)
    restore_mode = (restore_default or "").strip().lower() in {"1", "true", "yes", "on"}
    desired_pattern = profile.get("home_pattern", "") if restore_mode else (target_pattern or "").strip()
    if not desired_pattern:
      raise RuntimeError("Target translation pattern is required.")

    result = _update_twilio_inbound_verification_pattern(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      new_pattern=desired_pattern,
      profile_key=profile.get("key", ""),
    )

    auto_restore_enabled = False
    auto_restore_at_epoch_ms = 0
    if restore_mode:
      _cancel_twilio_inbound_auto_restore(profile.get("key", ""))
    elif desired_pattern != (profile.get("home_pattern", "") or ""):
      restore_at_epoch = _schedule_twilio_inbound_auto_restore(
        profile_key=profile.get("key", ""),
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
      )
      auto_restore_enabled = True
      auto_restore_at_epoch_ms = int(restore_at_epoch * 1000)
    else:
      _cancel_twilio_inbound_auto_restore(profile.get("key", ""))

    _append_audit_event(
      action="twilio_inbound_verification_update",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=(
        f"profile={profile.get('key', '')};"
        f"description={profile.get('description', '')};"
        f"old={result.get('old_pattern', '')};new={result.get('new_pattern', '')}"
      ),
      output_filename="inline_json_ok",
      inline_mode=True,
    )

    return JSONResponse(
      {
        "ok": True,
        **result,
        "auto_restore_enabled": auto_restore_enabled,
        "auto_restore_at_epoch_ms": auto_restore_at_epoch_ms,
        "auto_restore_seconds": TWILIO_INBOUND_AUTO_RESTORE_SECONDS if auto_restore_enabled else 0,
      }
    )


@app.post("/strike-mask/reverse")
def strike_mask_reverse_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    operation_id: str = Form(""),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    op_id = (operation_id or "").strip()
    if not op_id:
      raise RuntimeError("operation_id is required")

    result = _reverse_strike_mask_pattern(cucm_host, cucm_user, cucm_pass, op_id)

    _append_audit_event(
      action="strike_mask_reverse",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=(
        f"operation_id={op_id};"
        f"pattern={result.get('translation_pattern', '')};"
        f"description={result.get('new_description', '')}"
      ),
      output_filename="inline_json_ok",
      inline_mode=True,
    )

    _append_strike_mask_history_event(
      event="reverse",
      operation_id=result.get("operation_id", op_id),
      cucm_host=cucm_host,
      operator=cucm_user,
      target_user=result.get("target_user", ""),
      translation_pattern=result.get("translation_pattern", ""),
      translation_pattern_partition=result.get("translation_pattern_partition", ""),
      devices=result.get("devices_reverted", []),
      detail=f"description={result.get('new_description', '')};transform={result.get('new_transform_mask', '')}",
    )

    return JSONResponse({"ok": True, **result})


@app.post("/strike-mask/in-use")
def strike_mask_in_use_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    limit: int = Form(50),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    live_in_use = _list_in_use_strike_mask_patterns(cucm_host, cucm_user, cucm_pass)
    active_ops = _list_active_strike_mask_operations(limit=max(1, min(limit, 200)))

    return JSONResponse(
      {
        "ok": True,
        "count_live_in_use": len(live_in_use),
        "live_in_use_patterns": live_in_use,
        "count_active_operations": len(active_ops),
        "active_operations": active_ops,
      }
    )


@app.post("/strike-mask/options")
def strike_mask_options_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(""),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    clean_target = (target_user or "").strip()
    if not clean_target:
      raise RuntimeError("target_user is required")

    try:
      jabber_extension, jabber_devices = _find_jabber_extension(cucm_host, cucm_user, cucm_pass, clean_target)
      available_patterns = _find_available_945_patterns(cucm_host, cucm_user, cucm_pass)
    except RuntimeError:
      raise
    except Exception as exc:
      raise RuntimeError(f"Unable to load Strike Mask options for {clean_target}: {exc}") from exc

    available_patterns.sort(key=lambda item: (item.get("pattern") or ""))

    return JSONResponse(
      {
        "ok": True,
        "target_user": clean_target,
        "jabber_extension": jabber_extension,
        "devices": jabber_devices,
        "available_patterns": available_patterns,
      }
    )


@app.post("/strike-mask/apply")
def strike_mask_apply_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(""),
    selected_pattern: str = Form(""),
    selected_devices: str = Form(""),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

    clean_target = (target_user or "").strip()
    if not clean_target:
      raise RuntimeError("target_user is required")

    selected_device_names = [item.strip() for item in (selected_devices or "").split(",") if item.strip()]

    result = _apply_strike_mask_pattern(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=clean_target,
      operator=cucm_user,
      selected_pattern=selected_pattern,
      selected_device_names=selected_device_names,
    )

    _append_audit_event(
      action="strike_mask_apply",
      cucm_host=cucm_host,
      operator=cucm_user,
      target=(
        f"operation_id={result.get('operation_id', '')};"
        f"target_user={result.get('target_user', '')};"
        f"pattern={result.get('translation_pattern', '')}"
      ),
      output_filename="inline_json_ok",
      inline_mode=True,
    )

    _append_strike_mask_history_event(
      event="apply",
      operation_id=result.get("operation_id", ""),
      cucm_host=cucm_host,
      operator=cucm_user,
      target_user=result.get("target_user", ""),
      translation_pattern=result.get("translation_pattern", ""),
      translation_pattern_partition=result.get("translation_pattern_partition", ""),
      devices=result.get("devices_applied", []),
      detail=f"description={result.get('new_description', '')};transform={result.get('new_transform_mask', '')}",
    )

    return JSONResponse({"ok": True, **result})


@app.post("/verasmart/lab/queue/upload")
async def verasmart_lab_queue_upload_route(
    request: Request,
    csv_file: UploadFile = File(...),
):
    _session, operator = _require_admin_session(request)

    raw = await csv_file.read()
    text = raw.decode("utf-8-sig", errors="replace")
    rows = _parse_verasmart_queue_rows(text)
    if not rows:
      raise RuntimeError("No usable rows found. Include headers: record_key,target_change,note.")

    entry = _store_verasmart_queue_run(
      operator=operator,
      source_filename=(csv_file.filename or "verasmart_queue.csv"),
      rows=rows,
    )

    _append_audit_event(
      action="verasmart_lab_queue_upload",
      cucm_host=str((_session or {}).get("cucm_host", "") or ""),
      operator=operator,
      target=f"run_id={entry.get('run_id', '')};rows={entry.get('total_rows', 0)}",
      output_filename=entry.get("source_filename", ""),
      inline_mode=True,
    )

    return JSONResponse({
      "ok": True,
      "run_id": entry.get("run_id", ""),
      "total_rows": entry.get("total_rows", 0),
      "status": entry.get("status", ""),
      "note": entry.get("note", ""),
    })


@app.get("/verasmart/lab/queue/status")
def verasmart_lab_queue_status_route(
    request: Request,
    limit: int = Query(10),
):
    _require_admin_session(request)
    runs = _list_verasmart_queue_runs(limit=limit)
    return JSONResponse({"ok": True, "runs": runs, "count": len(runs)})


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

    # Always resolve from CUCM primary extension when phone not provided.
    if not phone:
        phone = _lookup_user_primary_extension(cucm_host, cucm_user, cucm_pass, clean_target)

    notify_status, notify_details = _send_csf_jabber_ready_email_if_created(
        cucm_host=cucm_host,
        cucm_user=cucm_user,
        cucm_pass=cucm_pass,
        target_user=clean_target,
        added_dn=phone,
    )

    ok = notify_status == "Success"
    try:
      _append_audit_event(
        action="send_jabber_ready_email",
        cucm_host=cucm_host,
        operator=cucm_user,
        target=clean_target,
        account=clean_target,
        extension_added=phone,
        extension_deleted="",
        output_filename="inline_json_ok" if ok else "inline_json_error",
        inline_mode=True,
      )
    except Exception:
      # Audit logging should not block the email response.
      pass

    if ok:
      return JSONResponse({"ok": True, "detail": notify_details})
    return JSONResponse({"ok": False, "detail": notify_details}, status_code=400)


@app.post("/send/mobile-jabber-email")
def send_mobile_jabber_email_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    target_user: str = Form(...),
):
    cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
    clean_target = (target_user or "").strip()

    # Always resolve phone number from CUCM primary extension.
    phone = _lookup_user_primary_extension(cucm_host, cucm_user, cucm_pass, clean_target)

    notify_status, notify_details = _send_mobile_jabber_ready_email(
      cucm_host=cucm_host,
      cucm_user=cucm_user,
      cucm_pass=cucm_pass,
      target_user=clean_target,
      phone_number=phone,
    )

    try:
      _append_audit_event(
        action="send_mobile_jabber_email",
        cucm_host=cucm_host,
        operator=cucm_user,
        target=clean_target,
        output_filename="",
        inline_mode=True,
        account=notify_status,
      )
    except Exception:
      # Do not fail the email response if audit logging has a transient issue.
      pass

    if notify_status == "Success":
        return JSONResponse({"ok": True, "detail": notify_details})
    else:
        return JSONResponse({"ok": False, "detail": notify_details}, status_code=400)


@app.post("/send/audit-trail-email")
def send_audit_trail_email_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
):
    session = _get_auth_session(request)
    if not session:
      return JSONResponse({"ok": False, "detail": "Authentication required."}, status_code=401)

    operator_username = (session.get("username") or "").strip()
    if not operator_username:
      return JSONResponse({"ok": False, "detail": "Could not resolve logged-in username."}, status_code=400)

    recipient = _derive_admin_audit_email(operator_username)
    if not recipient:
      return JSONResponse({"ok": False, "detail": "Could not derive recipient email from username."}, status_code=400)

    try:
      with AUDIT_LOG_LOCK:
        _ensure_audit_log()
        _prune_audit_log_locked()
        with open(AUDIT_LOG_PATH, "rb") as handle:
          audit_csv = handle.read()

      sender = (SMTP_DEFAULT_FROM or MOBILE_JABBER_EMAIL_FROM or "").strip()
      if not sender:
        return JSONResponse({"ok": False, "detail": "SMTP sender is not configured."}, status_code=400)

      ts = _audit_now().strftime("%Y-%m-%d %H:%M:%S")
      subject = f"CUCM Audit Trail - {ts}"
      audit_csv_text = audit_csv.decode("utf-8", errors="replace")
      body = (
        "Current CUCM portal audit trail CSV is included below, and attached as audit_trail.csv.\n\n"
        f"Requested by: {operator_username}\n"
        f"Recipient: {recipient}\n"
        "\n"
        "===== BEGIN AUDIT TRAIL CSV =====\n"
        f"{audit_csv_text}\n"
        "===== END AUDIT TRAIL CSV =====\n"
      )

      _send_smtp_email(
        sender=sender,
        recipients=[recipient],
        subject=subject,
        body=body,
        attachments=[("audit_trail.csv", audit_csv, "text/csv")],
      )

      try:
        resolved_host = (cucm_host or "").strip() or (session.get("cucm_host") or "")
        resolved_user = (cucm_user or "").strip() or operator_username
        _append_audit_event(
          action="send_audit_trail_email",
          cucm_host=resolved_host,
          operator=resolved_user,
          target=recipient,
          account=operator_username,
          output_filename="inline_audit_csv_body+attachment",
          inline_mode=True,
        )
      except Exception:
        pass

      return JSONResponse({"ok": True, "detail": f"Audit trail emailed to {recipient}."})
    except Exception as exc:
      return JSONResponse({"ok": False, "detail": str(exc)}, status_code=500)


@app.post("/lookup/person")
def lookup_person_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
  last_name: str = Form(""),
    first_name: str = Form(""),
  include_teams_status: str = Form(""),
  include_twilio_lookup: str = Form(""),
  include_aerialink_lookup: str = Form(""),
  twilio_lookup_account: str = Form("default"),
):
    try:
      cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
      _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)
      clean_last = (last_name or "").strip()
      clean_first = (first_name or "").strip()
      include_teams = str(include_teams_status or "").strip().lower() in {"1", "true", "yes", "on"}
      include_twilio = str(include_twilio_lookup or "").strip().lower() in {"1", "true", "yes", "on"}
      include_aerialink = str(include_aerialink_lookup or "").strip().lower() in {"1", "true", "yes", "on"}
      twilio_acct = str(twilio_lookup_account or "default").strip().lower()
      if not clean_last:
          raise RuntimeError("Last Name is required.")
      results = search_persons_by_name(cucm_host, cucm_user, cucm_pass, clean_last, clean_first)
      if include_teams:
        for user in results:
          uid = (user.get("userid") or "").strip()
          user["teams_telephony"] = {
            "is_teams_user": False,
            "status": "Not Found",
          }
          if not uid:
            continue
          try:
            candidate = lookup_teams_telephony_removal_candidate(cucm_host, cucm_user, cucm_pass, uid)
            is_teams_user = bool(candidate.get("match_found"))
            user["teams_telephony"] = {
              "is_teams_user": is_teams_user,
              "status": "Yes" if is_teams_user else "Not Found",
              "extension": (candidate.get("extension") or "").strip(),
              "pattern": (candidate.get("pattern") or "").strip(),
              "route_partition": (candidate.get("route_partition") or "").strip(),
            }
          except Exception:
            user["teams_telephony"] = {
              "is_teams_user": False,
              "status": "Unknown",
            }
      if include_twilio:
        for user in results:
          telephone = (user.get("telephone") or "").strip()
          user["twilio_lookup"] = _lookup_twilio_number_by_phone(telephone, account=twilio_acct)
      if include_aerialink:
        for user in results:
          telephone = (user.get("telephone") or "").strip()
          user["aerialink_lookup"] = _lookup_aerialink_account_code_by_phone(telephone)
      return JSONResponse({
          "ok": True,
          "count": len(results),
          "results": results,
          "query": {"last_name": clean_last, "first_name": clean_first},
      })
    except RuntimeError:
      raise
    except Exception as exc:
      raise RuntimeError(f"Person lookup failed: {exc}") from exc


@app.post("/lookup/twilio-by-number")
def lookup_twilio_by_number_route(phone_number: str = Form(...)):
    """Lookup Twilio provisioning status for a phone number."""
    try:
      clean_number = (phone_number or "").strip()
      if not clean_number:
        return JSONResponse({
            "ok": False,
            "error": "Phone number is required.",
            "result": None,
        }, status_code=400)
      
      result = _lookup_twilio_number_by_phone(clean_number, account="default")
      if not result.get("enabled"):
        return JSONResponse({
          "ok": False,
          "error": _build_lookup_error("Twilio AMIEWeb lookup", str(result.get("status", "Not configured")), "Set Twilio account SID/token environment variables and restart the service."),
          "result": result,
        }, status_code=503)
      return JSONResponse({
          "ok": True,
          "phone_number": clean_number,
          "result": result,
      })
    except Exception as exc:
      return JSONResponse({
          "ok": False,
          "error": str(exc),
          "result": None,
      }, status_code=500)


@app.post("/lookup/twilio-by-number-sfdc")
def lookup_twilio_by_number_sfdc_route(phone_number: str = Form(...)):
    """Lookup Twilio provisioning status for a phone number (Salesforce account)."""
    try:
      clean_number = (phone_number or "").strip()
      if not clean_number:
        return JSONResponse({
            "ok": False,
            "error": "Phone number is required.",
            "result": None,
        }, status_code=400)
      
      result = _lookup_twilio_number_by_phone(clean_number, account="salesforce")
      if not result.get("enabled"):
        return JSONResponse({
          "ok": False,
          "error": _build_lookup_error("Twilio Salesforce lookup", str(result.get("status", "Not configured")), "Set Twilio Salesforce subaccount SID/token environment variables and restart the service."),
          "result": result,
        }, status_code=503)
      return JSONResponse({
          "ok": True,
          "phone_number": clean_number,
          "result": result,
      })
    except Exception as exc:
      return JSONResponse({
          "ok": False,
          "error": str(exc),
          "result": None,
      }, status_code=500)


@app.post("/twilio/amieweb/sms-host")
def twilio_amieweb_sms_host_route(
  request: Request,
    phone_numbers: str = Form(""),
    sms_url: str = Form(""),
    sms_method: str = Form("POST"),
  friendly_name: str = Form(""),
    loa_recipient_name: str = Form(""),
    loa_recipient_email: str = Form(""),
    loa_recipient_phone: str = Form(""),
    loa_mode: str = Form("single"),
    loa_batch_reference: str = Form(""),
    sms_fallback_url: str = Form(""),
    sms_fallback_method: str = Form("POST"),
    status_callback_url: str = Form(""),
    status_callback_method: str = Form("POST"),
):
    try:
      if not TWILIO_HOSTED_NUMBERS_ACTIVE:
        return JSONResponse({
          "ok": False,
          "error": "Twilio SMS Hosting - AMIEWeb is NOT ACTIVE YET. Hosted Numbers API is in Developer Preview and currently disabled for this workflow.",
          "results": [],
        }, status_code=503)

      required_fields = [
        "phone_numbers (one or more, comma/newline separated)",
        "sms_method (GET or POST)",
      ]

      numbers = _parse_phone_number_input_list(phone_numbers)
      settings = _load_settings()
      clean_sms_url = (sms_url or "").strip() or TWILIO_AMIEWEB_DEFAULT_SMS_URL
      custom_friendly_name = (friendly_name or "").strip()
      operator_username = str((_get_auth_session(request) or {}).get("username", "") or "").strip()
      clean_loa_recipient_name = (loa_recipient_name or "").strip() or (settings.get("twilio_loa_recipient_name", "") or "").strip()
      clean_loa_recipient_email = (loa_recipient_email or "").strip() or (settings.get("twilio_loa_recipient_email", "") or "").strip()
      clean_loa_recipient_phone = (loa_recipient_phone or "").strip() or (settings.get("twilio_loa_recipient_phone", "") or "").strip()
      clean_loa_mode = "per_number" if (loa_mode or "").strip().lower() in {"per_number", "per-number", "pernumber"} else "single"
      clean_loa_batch_reference = (loa_batch_reference or "").strip()
      session_friendly_name = custom_friendly_name or f"host-{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
      subaccount_sid = _resolve_twilio_lookup_account_sid()
      subaccount_name = TWILIO_SUBACCOUNT_NAME or "AMIEWeb subaccount"
      if not numbers:
        return JSONResponse({
          "ok": False,
          "error": "At least one phone number is required.",
          "required_fields": required_fields,
          "results": [],
        }, status_code=400)
      if not clean_sms_url.lower().startswith("https://"):
        return JSONResponse({
          "ok": False,
          "error": "sms_url must be an HTTPS URL (or blank to use default).",
          "required_fields": required_fields,
          "results": [],
        }, status_code=400)

      payload = _build_twilio_sms_only_update_payload(
        sms_url=clean_sms_url,
        sms_method=sms_method,
        sms_fallback_url=sms_fallback_url,
        sms_fallback_method=sms_fallback_method,
        status_callback_url=status_callback_url,
        status_callback_method=status_callback_method,
        friendly_name=custom_friendly_name,
      )

      seed = _get_twilio_next_friendly_name_seed(account="default")
      auto_prefix = str(seed.get("date_prefix", "") or "")
      auto_index = int(seed.get("next_index", 1) or 1)
      if not auto_prefix:
        auto_prefix = datetime.datetime.now().strftime("%Y%m%d")

      results = []
      success_count = 0
      for idx, number in enumerate(numbers):
        row_payload = dict(payload)
        row_payload["FriendlyName"] = session_friendly_name

        row = _twilio_update_sms_only_for_number(
          number,
          row_payload,
          loa_recipient_name=clean_loa_recipient_name,
          loa_recipient_email=clean_loa_recipient_email,
          loa_recipient_phone=clean_loa_recipient_phone,
          loa_mode=clean_loa_mode,
          loa_batch_reference=clean_loa_batch_reference,
        )

        row_sid = str(row.get("sid", "") or "").strip()
        if row.get("ok") and row.get("action") == "Updated" and row_sid.startswith("PN"):
          attach_ok, attach_status = _twilio_attach_phone_to_messaging_service(
            _resolve_twilio_lookup_account_sid(),
            _resolve_twilio_lookup_auth_token_for_sid(_resolve_twilio_lookup_account_sid()),
            row_sid,
          )
          row["messaging_service_sid"] = TWILIO_AMIEWEB_MESSAGING_SERVICE_SID
          row["messaging_service_status"] = attach_status if attach_ok else f"Failed: {attach_status}"
        if not row.get("friendly_name"):
          row["friendly_name"] = session_friendly_name
        if row.get("ok"):
          success_count += 1
        results.append(row)

      audit_rows = []
      now_text = _audit_now().strftime(AUDIT_TIMESTAMP_FORMAT)
      for row in results:
        audit_rows.append({
          "timestamp": now_text,
          "submitter": operator_username,
          "session_friendly_name": session_friendly_name,
          "input_number": str(row.get("input", "") or ""),
          "normalized_number": str(row.get("normalized", "") or ""),
          "phone_sid": str(row.get("sid", "") or ""),
          "verification_code": str(row.get("verification_code", "") or ""),
          "verification_status": "pending" if str(row.get("verification_code", "") or "").strip() else "n/a",
          "result_action": str(row.get("action", "") or ""),
          "result_status": str(row.get("status", "") or ""),
          "loa_mode": clean_loa_mode,
          "loa_batch_reference": clean_loa_batch_reference,
          "loa_recipient_name": clean_loa_recipient_name,
          "loa_recipient_email": clean_loa_recipient_email,
          "loa_recipient_phone": clean_loa_recipient_phone,
          "messaging_service_sid": str(row.get("messaging_service_sid", "") or TWILIO_AMIEWEB_MESSAGING_SERVICE_SID),
          "messaging_service_status": str(row.get("messaging_service_status", "") or ""),
        })
      _append_twilio_sms_hosting_audit_rows(audit_rows)

      return JSONResponse({
        "ok": True,
        "required_fields": required_fields,
        "summary": {
          "requested": len(numbers),
          "updated": success_count,
          "failed": len(numbers) - success_count,
        },
        "submitted": {
          "sms_url": payload.get("SmsUrl", ""),
          "sms_method": payload.get("SmsMethod", "POST"),
          "friendly_name": session_friendly_name,
          "friendly_name_mode": "custom" if custom_friendly_name else "session_auto",
          "friendly_name_auto_seed": f"{auto_prefix}_{auto_index}",
          "subaccount_name": subaccount_name,
          "subaccount_sid": subaccount_sid,
          "loa_recipient_name": clean_loa_recipient_name,
          "loa_recipient_email": clean_loa_recipient_email,
          "loa_recipient_phone": clean_loa_recipient_phone,
          "loa_mode": clean_loa_mode,
          "loa_batch_reference": clean_loa_batch_reference,
          "sms_fallback_url": payload.get("SmsFallbackUrl", ""),
          "sms_fallback_method": payload.get("SmsFallbackMethod", ""),
          "status_callback_url": payload.get("StatusCallback", ""),
          "status_callback_method": payload.get("StatusCallbackMethod", ""),
        },
        "results": results,
      })
    except Exception as exc:
      return JSONResponse({
        "ok": False,
        "error": str(exc),
        "results": [],
      }, status_code=500)


@app.get("/download/twilio-sms-hosting-audit")
def download_twilio_sms_hosting_audit():
  with TWILIO_SMS_HOSTING_AUDIT_LOCK:
    _ensure_twilio_sms_hosting_audit_log()
    _prune_twilio_sms_hosting_audit_locked()
    with open(TWILIO_SMS_HOSTING_AUDIT_PATH, "rb") as handle:
      data = handle.read()

  return Response(
    data,
    media_type="text/csv",
    headers={"Content-Disposition": 'attachment; filename="twilio_sms_hosting_audit.csv"'},
  )


@app.get("/twilio/amieweb/friendly-name-status")
def twilio_amieweb_friendly_name_status(
  friendly_name: str = "",
  limit: int = 50,
):
  clean_name = (friendly_name or "").strip()
  safe_limit = max(1, min(limit, 200))
  rows = _load_twilio_sms_hosting_audit_rows(limit=500)
  if clean_name:
    rows = [row for row in rows if str(row.get("session_friendly_name", "") or "").strip() == clean_name]
  rows = rows[:safe_limit]

  return JSONResponse({
    "ok": True,
    "count": len(rows),
    "friendly_name": clean_name,
    "rows": rows,
  })


@app.post("/twilio/amieweb/verification/mark")
def twilio_amieweb_verification_mark(
  request: Request,
  friendly_name: str = Form(""),
  normalized_number: str = Form(""),
  verification_status: str = Form("pending"),
  notes: str = Form(""),
):
  session = _get_auth_session(request) or {}
  operator = str(session.get("username", "") or "").strip()
  clean_name = (friendly_name or "").strip()
  clean_number = (normalized_number or "").strip()
  clean_status = (verification_status or "pending").strip().lower()
  clean_notes = (notes or "").strip()
  if clean_status not in {"pending", "verified", "failed", "skipped"}:
    clean_status = "pending"

  _append_twilio_sms_hosting_audit_rows([
    {
      "timestamp": _audit_now().strftime(AUDIT_TIMESTAMP_FORMAT),
      "submitter": operator,
      "session_friendly_name": clean_name,
      "input_number": clean_number,
      "normalized_number": clean_number,
      "phone_sid": "",
      "verification_code": "",
      "verification_status": clean_status,
      "result_action": "VerificationUpdate",
      "result_status": clean_notes,
      "loa_mode": "",
      "loa_batch_reference": "",
      "loa_recipient_name": "",
      "loa_recipient_email": "",
      "loa_recipient_phone": "",
      "messaging_service_sid": TWILIO_AMIEWEB_MESSAGING_SERVICE_SID,
      "messaging_service_status": "",
    }
  ])

  return JSONResponse({"ok": True})


@app.post("/lookup/aerialink-by-number")
def lookup_aerialink_by_number_route(phone_number: str = Form(...)):
    """Lookup Aerialink provisioning status for a phone number."""
    try:
      clean_number = (phone_number or "").strip()
      if not clean_number:
        return JSONResponse({
            "ok": False,
            "error": "Phone number is required.",
            "result": None,
        }, status_code=400)
      
      result = _lookup_aerialink_account_code_by_phone(clean_number)
      if not result.get("enabled"):
        return JSONResponse({
            "ok": False,
            "error": str(result.get("status") or _build_lookup_error("Aerialink lookup", "Not configured")),
            "result": result,
        }, status_code=503)
      return JSONResponse({
          "ok": True,
          "phone_number": clean_number,
          "result": result,
      })
    except Exception as exc:
      return JSONResponse({
          "ok": False,
          "error": str(exc),
          "result": None,
      }, status_code=500)


@app.post("/lookup/sms-number-look")
def lookup_sms_number_look_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    last_name: str = Form(""),
    first_name: str = Form(""),
    phone_number: str = Form(""),
):
    try:
      if not SMS_NUMBER_LOOKUP_ENABLED:
        raise RuntimeError("SMS Number Lookup is currently disabled.")

      cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
      _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user)

      clean_phone = (phone_number or "").strip()
      clean_last = (last_name or "").strip()
      clean_first = (first_name or "").strip()

      def _build_platform_row(display_name: str, extension: str, telephone: str) -> dict:
        twilio_default = _lookup_twilio_number_by_phone(telephone, account="default")
        twilio_sfdc = _lookup_twilio_number_by_phone(telephone, account="salesforce")
        aerialink = _lookup_aerialink_account_code_by_phone(telephone)

        found_in = []
        if twilio_default.get("found"):
          found_in.append("Twilio - AMIEWeb")
        if twilio_sfdc.get("found"):
          found_in.append("Twilio - Salesforce")
        if aerialink.get("provisioned"):
          found_in.append("Aerialink Classic")

        sms_number = (
          (twilio_default.get("phone_number") or "").strip()
          or (twilio_sfdc.get("phone_number") or "").strip()
          or (aerialink.get("matched_number") or "").strip()
          or _normalize_phone_to_e164(telephone)
          or (telephone or "").strip()
        )

        return {
          "display_name": display_name or "-",
          "extension": extension or "-",
          "sms_number": sms_number or "-",
          "configured_in": ", ".join(found_in) if found_in else "Not Found",
        }

      results = []
      mode = ""

      if clean_phone:
        mode = "number"
        results.append(_build_platform_row(display_name="(Direct Number Lookup)", extension="-", telephone=clean_phone))
      else:
        mode = "name"
        if not clean_last:
          raise RuntimeError("Last Name is required when phone number is not provided.")

        users = search_persons_by_name(cucm_host, cucm_user, cucm_pass, clean_last, clean_first)
        for user in users:
          if not isinstance(user, dict):
            continue
          display_name = (user.get("display_name") or "").strip() or (
            (user.get("first_name") or "") + " " + (user.get("last_name") or "")
          ).strip() or (user.get("userid") or "")
          extension = (user.get("primary_extension") or "").strip()
          telephone = (user.get("telephone") or "").strip()
          results.append(_build_platform_row(display_name=display_name, extension=extension, telephone=telephone))

      return JSONResponse({
        "ok": True,
        "mode": mode,
        "count": len(results),
        "results": results,
      })
    except RuntimeError:
      raise
    except Exception as exc:
      raise RuntimeError(f"SMS Number Lookup failed: {exc}") from exc


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

    duplicate_warnings = _build_jabber_precheck_warnings(result)
    result["duplicate_warnings"] = duplicate_warnings
    result["can_proceed"] = not duplicate_warnings

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
      .card {{ max-width: 960px; background: #ffffff; border: 1px solid #d7e2ee; border-radius: 12px; padding: 18px; box-shadow: 0 8px 20px rgba(0, 47, 108, 0.08); }}
      .precheck-banner {{ border-radius: 10px; padding: 14px 16px; margin: 14px 0 16px 0; border: 1px solid #cfe1f3; background: #eef6ff; }}
      .precheck-banner.warning {{ border-color: #f0c36d; background: #fff8e8; }}
      .precheck-banner.ok {{ border-color: #9fd1b6; background: #eefaf2; }}
      .precheck-banner h3 {{ margin: 0 0 8px 0; font-size: 18px; }}
      .precheck-banner ul {{ margin: 8px 0 0 18px; padding: 0; }}
      .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; margin: 14px 0; }}
      .summary-item {{ border: 1px solid #d7e2ee; border-radius: 10px; padding: 12px; background: #f9fcff; }}
      .summary-label {{ display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #5d7690; margin-bottom: 4px; }}
      .summary-value {{ font-weight: 700; color: #10324f; }}
      pre {{ background: #eef5fb; border: 1px solid #d7e2ee; border-radius: 8px; padding: 12px; white-space: pre-wrap; }}
      a {{ color: #005cb9; font-weight: 600; }}
    </style>
  </head>
  <body>
    <div class=\"card\">
      <h2>Jabber Pre-Check Result</h2>
      <div class=\"precheck-banner {'warning' if duplicate_warnings else 'ok'}\">
        <h3>{'Duplicate resources found' if duplicate_warnings else 'No duplicate Jabber resources found'}</h3>
        <div>{'Review the items below before building.' if duplicate_warnings else 'You can proceed with the build workflow.'}</div>
        {f"<ul>{''.join(f'<li>{escape(item)}</li>' for item in duplicate_warnings)}</ul>" if duplicate_warnings else ''}
      </div>
      <div class=\"summary-grid\">
        <div class=\"summary-item\"><span class=\"summary-label\">User</span><span class=\"summary-value\">{escape(result.get('target_user', '') or 'Not found')}</span></div>
        <div class=\"summary-item\"><span class=\"summary-label\">Jabber Built</span><span class=\"summary-value\">{'YES' if result.get('jabber_built') else 'NO'}</span></div>
        <div class=\"summary-item\"><span class=\"summary-label\">Device Name</span><span class=\"summary-value\">{escape(result.get('device_name') or 'Not found')}</span></div>
        <div class=\"summary-item\"><span class=\"summary-label\">Jabber Extension</span><span class=\"summary-value\">{escape(result.get('extension') or 'Not found')}</span></div>
        <div class=\"summary-item\"><span class=\"summary-label\">Voicemail Extension</span><span class=\"summary-value\">{escape(result.get('voicemail_extension') or 'Not found')}</span></div>
        <div class=\"summary-item\"><span class=\"summary-label\">Environment</span><span class=\"summary-value\">{escape(result.get('environment', '') or '')}</span></div>
      </div>
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
      pin_reset_meta = {"reset_success": False}
    else:
      data, filename, pin_reset_meta = reset_unity_voicemail_pin(
        unity_server=unity_server,
        unity_user=unity_user,
        unity_pass=unity_pass,
        target_alias=voicemail_user,
        new_pin=new_voicemail_pin,
      )

    email_status = ""
    if pin_reset_meta.get("reset_success"):
      target_email = pin_reset_meta.get("email", "")
      extension = pin_reset_meta.get("extension", "")
      ext_digits = "".join(c for c in extension if c.isdigit())
      if len(ext_digits) == 10:
        ext_display = f"{ext_digits[:3]}-{ext_digits[3:6]}-{ext_digits[6:]}"
      elif len(ext_digits) == 11 and ext_digits.startswith("1"):
        ext_display = f"{ext_digits[1:4]}-{ext_digits[4:7]}-{ext_digits[7:]}"
      else:
        ext_display = extension or voicemail_user
      if target_email:
        try:
          _send_smtp_email(
            sender="noreply@amnhealthcare.com",
            recipients=[target_email],
            subject=f"Voicemail PIN reset for Jabber Extension {ext_display}",
            body=(
              f"A voicemail PIN reset was initiated. Your new voicemail pin is {new_voicemail_pin}#.\n\n"
              f"If this request was not initiated by you, please contact our IT Service Desk at 855-435-7822."
            ),
            html_body=(
              f"<p>A voicemail PIN reset was initiated. Your new voicemail pin is <strong>{new_voicemail_pin}#</strong>.</p>"
              f"<p>If this request was not initiated by you, please contact our IT Service Desk at <strong>855-435-7822</strong>.</p>"
            ),
          )
          email_status = f"Notification email sent to {target_email}."
        except Exception as _email_exc:
          email_status = f"PIN reset succeeded but email notification failed: {_email_exc}"
      else:
        email_status = "PIN reset succeeded. No email address on file; notification not sent."

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
        "email_status": email_status,
      })

    return _render_job_result("Reset Unity Voicemail PIN - with email notification", data, filename)


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


@app.post("/admin/ldap-sync")
def admin_ldap_sync_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    inline: bool = Query(False),
):
  cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
  _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user, cucm_pass=cucm_pass)

  cucm_host = _get_runtime_cucm_host(cucm_host)
  agreement = LAB_LDAP_AGREEMENT if _is_lab_environment(cucm_host) else PROD_LDAP_AGREEMENT

  now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
  safe_agreement = re.sub(r"[^A-Za-z0-9_-]+", "_", agreement)
  filename = f"ldap_sync_{safe_agreement}_{now}.csv"

  env_text, _ = _get_environment_label(cucm_host)

  rows = [["Step", "Status", "Details"]]
  rows.append(["Environment", "Info", f"{env_text} ({cucm_host})"])
  rows.append(["LDAP Agreement", "Info", agreement])

  try:
    ok, message = _trigger_cucm_ldap_sync(cucm_host, cucm_user, cucm_pass, agreement)
    rows.append(["LDAP Sync", "Success" if ok else "Failed", message])
  except Exception as exc:
    rows.append(["LDAP Sync", "Failed", str(exc)])

  csv_data = io.StringIO()
  writer = csv.writer(csv_data)
  writer.writerows(rows)
  data = csv_data.getvalue().encode("utf-8")

  _append_audit_event(
    action="admin_ldap_sync",
    cucm_host=cucm_host,
    operator=cucm_user,
    target=agreement,
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

  return _render_job_result("CUCM LDAP Sync", data, filename, back_url="/page2")


@app.post("/admin/unity-ldap-sync")
def admin_unity_ldap_sync_route(
    request: Request,
    cucm_host: str = Form(""),
    cucm_user: str = Form(""),
    cucm_pass: str = Form(""),
    unity_user: str = Form(""),
    unity_pass: str = Form(""),
    inline: bool = Query(False),
):
  cucm_host, cucm_user, cucm_pass = _resolve_cucm_credentials(request, cucm_host, cucm_user, cucm_pass)
  _update_cached_credentials(request, cucm_host=cucm_host, cucm_user=cucm_user, cucm_pass=cucm_pass)

  unity_user, unity_pass = _resolve_unity_credentials(request, unity_user, unity_pass)
  cucm_host = _get_runtime_cucm_host(cucm_host)
  unity_server = _get_runtime_unity_host(_get_unity_server_for_session(request))

  now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
  unity_label = "LAB" if (unity_server or "").strip().lower() == LAB_UNITY_HOST.lower() else "PROD"
  filename = f"unity_ldap_sync_{unity_label}_{now}.csv"

  env_text, _ = _get_environment_label(cucm_host)

  rows = [["Step", "Status", "Details"]]
  rows.append(["Environment", "Info", f"{env_text} ({cucm_host})"])
  rows.append(["Unity Server", "Info", unity_server])

  try:
    ok, message = _trigger_unity_ldap_sync(unity_server, unity_user, unity_pass)
    rows.append(["Unity LDAP Sync", "Success" if ok else "Failed", message])
  except Exception as exc:
    rows.append(["Unity LDAP Sync", "Failed", str(exc)])

  csv_data = io.StringIO()
  writer = csv.writer(csv_data)
  writer.writerows(rows)
  data = csv_data.getvalue().encode("utf-8")

  _append_audit_event(
    action="admin_unity_ldap_sync",
    cucm_host=cucm_host,
    operator=cucm_user,
    target=unity_server,
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

  return _render_job_result("Unity LDAP Sync", data, filename, back_url="/page2")


@app.get("/admin/separation-sms-report/config")
def sep_sms_report_config_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)

  cfg = _get_sep_report_settings()
  freq = cfg["frequency"]
  hour = cfg["hour"]
  minute = cfg["minute"]
  schedule_label = (
    f"{hour:02d}:{minute:02d} PST/PDT daily" if freq == "daily"
    else f"{cfg['weekly_day'].capitalize()} at {hour:02d}:{minute:02d} PST/PDT (prior Mon\u2013Sun window)"
  )

  return JSONResponse({
    "ok": True,
    "enabled": cfg["enabled"],
    "recipient": cfg["recipient"],
    "recipient_2": cfg["recipient_2"],
    "from_address": cfg["from_address"],
    "frequency": freq,
    "hour": hour,
    "minute": minute,
    "weekly_day": cfg["weekly_day"] if freq == "weekly" else cfg["weekly_day"],
    "schedule_label": schedule_label,
  })


@app.post("/admin/separation-sms-report/save-config")
async def sep_sms_report_save_config_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)

  try:
    body = await request.json()
  except Exception:
    return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)

  recipient = (body.get("recipient") or "").strip()
  recipient_2 = (body.get("recipient_2") or "").strip()
  from_address = (body.get("from_address") or "").strip()
  enabled = str(body.get("enabled", "true")).strip().lower() in {"1", "true", "yes", "on"}
  frequency = (body.get("frequency") or "daily").strip().lower()
  if frequency not in {"daily", "weekly"}:
    frequency = "daily"
  weekly_day = (body.get("weekly_day") or "monday").strip().lower()
  _VALID_DAYS = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
  if weekly_day not in _VALID_DAYS:
    weekly_day = "monday"

  try:
    hour = int(body.get("hour", 8))
    minute = int(body.get("minute", 0))
  except (TypeError, ValueError):
    return JSONResponse({"ok": False, "error": "Hour and minute must be integers"}, status_code=400)

  if not (0 <= hour <= 23):
    return JSONResponse({"ok": False, "error": "Hour must be 0–23"}, status_code=400)
  if not (0 <= minute <= 59):
    return JSONResponse({"ok": False, "error": "Minute must be 0–59"}, status_code=400)
  if not recipient:
    return JSONResponse({"ok": False, "error": "Primary recipient email is required"}, status_code=400)

  settings = _load_settings()
  settings["sep_report_enabled"] = "true" if enabled else "false"
  settings["sep_report_recipient"] = recipient
  settings["sep_report_recipient_2"] = recipient_2
  settings["sep_report_from"] = from_address
  settings["sep_report_hour"] = str(hour)
  settings["sep_report_minute"] = str(minute)
  settings["sep_report_frequency"] = frequency
  settings["sep_report_weekly_day"] = weekly_day

  if not _save_settings(settings):
    return JSONResponse({"ok": False, "error": "Failed to save settings file"}, status_code=500)

  return JSONResponse({"ok": True, "message": "Settings saved successfully."})


@app.post("/admin/separation-sms-report/run")
def sep_sms_report_run_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)

  operator = str(session.get("username", "manual")).strip() or "manual"
  result = _run_separation_sms_report(triggered_by=f"manual:{operator}")
  if result.get("success"):
    return JSONResponse({
      "ok": True,
      "date_range": result.get("date_range", ""),
      "numbers_checked": result.get("numbers_checked", 0),
      "numbers_found_in_sms": result.get("numbers_found_in_sms", 0),
      "recipients": result.get("recipients", []),
    })
  return JSONResponse({"ok": False, "error": result.get("error", "Unknown error")}, status_code=500)


@app.get("/admin/separation-sms-report/history")
def sep_sms_report_history_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)

  if not os.path.exists(AUDIT_LOG_PATH):
    return JSONResponse({"ok": True, "rows": []})

  try:
    with AUDIT_LOG_LOCK:
      with open(AUDIT_LOG_PATH, "r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        all_rows = list(reader)
  except Exception as exc:
    return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

  history = []
  for row in reversed(all_rows):
    if (row.get("action") or "").strip() != "separation_sms_report_sent":
      continue
    # Parse the period out of target field: "period=XXXX;extensions_checked=N"
    target_raw = row.get("target", "")
    period = ""
    for part in target_raw.split(";"):
      if part.startswith("period="):
        period = part[len("period="):]
        break
    history.append({
      "timestamp": row.get("timestamp", ""),
      "period": period,
      "account": row.get("account", ""),
      "extension_deleted": row.get("extension_deleted", ""),
      "operator": row.get("operator", ""),
    })
    if len(history) >= 20:
      break

  return JSONResponse({"ok": True, "rows": history})


@app.get("/admin/dn-avail-report/config")
def dn_avail_report_config_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)
  cfg = _get_dn_report_settings()
  return JSONResponse({
    "ok": True,
    "enabled": cfg["enabled"],
    "recipient": cfg["recipient"],
    "recipient_2": cfg["recipient_2"],
    "from_address": cfg["from_address"],
    "hour": cfg["hour"],
    "minute": cfg["minute"],
    "frequency": cfg["frequency"],
    "cucm_host": cfg["cucm_host"],
    "cucm_user": cfg["cucm_user"],
    # Never return password
    "low_threshold": cfg["low_threshold"],
  })


@app.post("/admin/dn-avail-report/save-config")
async def dn_avail_report_save_config_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)
  try:
    body = await request.json()
  except Exception:
    return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)

  recipient = (body.get("recipient") or "").strip()
  if not recipient:
    return JSONResponse({"ok": False, "error": "Primary recipient email is required"}, status_code=400)
  try:
    hour = int(body.get("hour", 8))
    minute = int(body.get("minute", 0))
    low_threshold = int(body.get("low_threshold", 10))
  except (TypeError, ValueError):
    return JSONResponse({"ok": False, "error": "Hour, minute, and threshold must be integers"}, status_code=400)
  if not (0 <= hour <= 23) or not (0 <= minute <= 59) or low_threshold < 1:
    return JSONResponse({"ok": False, "error": "Invalid hour, minute, or threshold value"}, status_code=400)

  enabled = str(body.get("enabled", "true")).strip().lower() in {"1", "true", "yes", "on"}
  frequency = (body.get("frequency") or "daily").strip().lower()
  if frequency not in {"daily", "weekly"}:
    frequency = "daily"

  settings = _load_settings()
  settings["dn_report_enabled"] = "true" if enabled else "false"
  settings["dn_report_recipient"] = recipient
  settings["dn_report_recipient_2"] = (body.get("recipient_2") or "").strip()
  settings["dn_report_from"] = (body.get("from_address") or "").strip()
  settings["dn_report_hour"] = str(hour)
  settings["dn_report_minute"] = str(minute)
  settings["dn_report_frequency"] = frequency
  settings["dn_report_cucm_host"] = (body.get("cucm_host") or "").strip()
  settings["dn_report_cucm_user"] = (body.get("cucm_user") or "").strip()
  settings["dn_report_low_threshold"] = str(low_threshold)
  # Only overwrite password if a new one was provided
  new_pass = (body.get("cucm_pass") or "").strip()
  if new_pass:
    settings["dn_report_cucm_pass"] = new_pass

  if not _save_settings(settings):
    return JSONResponse({"ok": False, "error": "Failed to save settings file"}, status_code=500)
  return JSONResponse({"ok": True, "message": "Settings saved successfully."})


@app.post("/admin/dn-avail-report/run")
def dn_avail_report_run_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)
  operator = str(session.get("username", "manual")).strip() or "manual"
  result = _run_dn_availability_report(triggered_by=f"manual:{operator}")
  if result.get("success"):
    cfg = _get_dn_report_settings()
    return JSONResponse({
      "ok": True,
      "run_at": result.get("run_at", ""),
      "recipients": result.get("recipients", []),
      "results": result.get("results", []),
      "errors": result.get("errors", []),
      "low_threshold": cfg["low_threshold"],
    })
  return JSONResponse({"ok": False, "error": result.get("error", "Unknown error")}, status_code=500)


@app.get("/admin/dn-avail-report/history")
def dn_avail_report_history_route(request: Request):
  session = _get_auth_session(request)
  if not session or not _is_admin_user(str(session.get("username", ""))):
    return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)
  if not os.path.exists(AUDIT_LOG_PATH):
    return JSONResponse({"ok": True, "rows": []})
  try:
    with AUDIT_LOG_LOCK:
      with open(AUDIT_LOG_PATH, "r", newline="", encoding="utf-8") as fh:
        all_rows = list(csv.DictReader(fh))
  except Exception as exc:
    return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

  history = []
  for row in reversed(all_rows):
    if (row.get("action") or "").strip() != "dn_avail_report_sent":
      continue
    target_raw = row.get("target", "")
    summary = ""
    for part in target_raw.split(";"):
      if part.startswith("summary="):
        summary = part[len("summary="):]
        break
    history.append({
      "timestamp": row.get("timestamp", ""),
      "summary": summary,
      "account": row.get("account", ""),
      "operator": row.get("operator", ""),
    })
    if len(history) >= 20:
      break
  return JSONResponse({"ok": True, "rows": history})


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

    return _render_job_result("STRIKE MODE - Add Secondary Device Jabber TCT and BOT (Option 5)", data, filename, back_url="/page2")


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

  return _render_job_result("Remove only Jabber Mobile - iPhone or Android", data, filename, back_url="/page2")


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

    return _render_job_result("Edit Line Group Members (Option 17)", data, filename, back_url="/page2")


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

    return _render_job_result("Extract RPO Phones (Option 18)", data, filename, back_url="/page2")

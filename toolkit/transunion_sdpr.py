import os
import re

import requests


TRANSUNION_API_ENABLED = (os.getenv("TRANSUNION_API_ENABLED", "false") or "false").strip().lower() in {"1", "true", "yes", "on"}
TRANSUNION_API_ENV = (os.getenv("TRANSUNION_API_ENV", "uat") or "uat").strip().lower()
TRANSUNION_BASE_URL = (os.getenv("TRANSUNION_BASE_URL", "https://api-uat-rst.ccid.neustar.biz") or "").strip().rstrip("/")
TRANSUNION_ACCOUNT_ID = (os.getenv("TRANSUNION_ACCOUNT_ID", "") or "").strip()
TRANSUNION_API_USER = (os.getenv("TRANSUNION_API_USER", "") or "").strip()
TRANSUNION_API_PASSWORD = os.getenv("TRANSUNION_API_PASSWORD", "") or ""
TRANSUNION_API_TIMEOUT_SECONDS = int((os.getenv("TRANSUNION_API_TIMEOUT_SECONDS", "30") or "30").strip())
AAM_BASE_PATH = "/ccid/aam/v1"
SDPR_BASE_PATH = "/ccid/sdpr/v4/admin"


def _configuration_error():
  if not TRANSUNION_API_ENABLED:
    return "TransUnion integration is disabled."
  if TRANSUNION_API_ENV != "uat":
    return "Only the UAT TransUnion environment is enabled."
  missing = [name for name, value in (("TRANSUNION_BASE_URL", TRANSUNION_BASE_URL), ("TRANSUNION_ACCOUNT_ID", TRANSUNION_ACCOUNT_ID), ("TRANSUNION_API_USER", TRANSUNION_API_USER), ("TRANSUNION_API_PASSWORD", TRANSUNION_API_PASSWORD)) if not value]
  return f"Missing TransUnion configuration: {', '.join(missing)}." if missing else ""


def _request(method, path, token="", params=None, json_body=None):
  headers = {"Accept": "application/json"}
  if token:
    headers["Authorization"] = f"Bearer {token}"
  if json_body is not None:
    headers["Content-Type"] = "application/json"
  try:
    response = requests.request(method, f"{TRANSUNION_BASE_URL}{path}", headers=headers, params=params or {}, json=json_body, timeout=TRANSUNION_API_TIMEOUT_SECONDS)
  except requests.RequestException as exc:
    return {"ok": False, "status_code": 0, "error": f"TransUnion request failed: {exc}"}
  try:
    payload = response.json() if response.text else {}
  except ValueError:
    payload = {"raw": (response.text or "")[:1000]}
  if not 200 <= response.status_code < 300:
    message = str(payload.get("reason") or payload.get("message") or payload.get("developer_message") or "").strip() if isinstance(payload, dict) else ""
    return {"ok": False, "status_code": response.status_code, "error": message or f"HTTP {response.status_code}", "raw": payload}
  return {"ok": True, "status_code": response.status_code, "data": payload}


def login():
  error = _configuration_error()
  if error:
    return {"ok": False, "status_code": 0, "error": error}
  return _request("POST", f"{AAM_BASE_PATH}/login", json_body={"userId": TRANSUNION_API_USER, "password": TRANSUNION_API_PASSWORD})


def _get_access_token():
  result = login()
  if not result.get("ok"):
    return result
  payload = result.get("data") or {}
  token = str(payload.get("accessToken", "") if isinstance(payload, dict) else "").strip()
  return {"ok": True, "token": token} if token else {"ok": False, "status_code": 502, "error": "TransUnion login did not return accessToken.", "raw": payload}


def integration_status():
  result = _get_access_token()
  return result if not result.get("ok") else {"ok": True, "status_code": 200, "message": "TransUnion UAT login succeeded."}


def list_caller_profiles(limit=100, offset=0):
  token_result = _get_access_token()
  if not token_result.get("ok"):
    return token_result
  return _request("GET", f"{SDPR_BASE_PATH}/caller-profile", token=token_result["token"], params={"accountId": TRANSUNION_ACCOUNT_ID, "limit": max(1, min(int(limit), 500)), "offset": max(0, int(offset))})


def create_caller_profile(caller_name, services=None, branded_caller_name="", name=""):
  clean_caller_name = str(caller_name or "").strip()
  service_names = [str(value or "").strip().upper() for value in (services or []) if str(value or "").strip()]
  allowed_services = {"CNO", "LANDLINE-NAME", "NAME-BCD", "AUTH-BCD", "RICH-BCD", "RICH-BCD-W-NAME-FALLBACK", "DNO", "SPOOF-CALL-PROTECTION"}
  invalid = sorted(set(service_names) - allowed_services)
  if not clean_caller_name or len(clean_caller_name) > 15:
    return {"ok": False, "status_code": 400, "error": "caller_name is required and must be 1-15 characters."}
  if not service_names:
    return {"ok": False, "status_code": 400, "error": "At least one Caller Profile service is required."}
  if invalid:
    return {"ok": False, "status_code": 400, "error": f"Unsupported service(s): {', '.join(invalid)}."}
  token_result = _get_access_token()
  if not token_result.get("ok"):
    return token_result
  partners = [{"name": partner, "status": "TU-Review-Requested"} for partner in ("att", "verizon", "tmobile")]
  body = {"account_id": TRANSUNION_ACCOUNT_ID, "caller_name": clean_caller_name, "service": [{"name": service_name, "partner": partners} for service_name in dict.fromkeys(service_names)]}
  if str(name or "").strip():
    body["name"] = str(name).strip()
  if str(branded_caller_name or "").strip():
    clean_branded_name = str(branded_caller_name).strip()
    if len(clean_branded_name) > 32:
      return {"ok": False, "status_code": 400, "error": "branded_caller_name must be 1-32 characters."}
    body["branded_caller_name"] = clean_branded_name
  return _request("POST", f"{SDPR_BASE_PATH}/caller-profile", token=token_result["token"], json_body=body)


def list_tn_assets(number="", caller_profile="", limit=100, offset=0):
  token_result = _get_access_token()
  if not token_result.get("ok"):
    return token_result
  params = {"accountId": TRANSUNION_ACCOUNT_ID, "limit": max(1, min(int(limit), 500)), "offset": max(0, int(offset)), "exact": "true"}
  digits = re.sub(r"\D", "", str(number or ""))
  if digits:
    params["tn"] = f"+1.{digits[-10:]}"
  if str(caller_profile or "").strip():
    params["callerProfile"] = str(caller_profile).strip()
  return _request("GET", f"{SDPR_BASE_PATH}/orig/tcs/asset", token=token_result["token"], params=params)

from urllib.parse import urljoin, urlsplit

import requests


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
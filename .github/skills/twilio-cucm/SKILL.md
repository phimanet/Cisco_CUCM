---
name: twilio-cucm
description: "Use when changing Twilio, CUCM SMS, Messaging Service, TwiML App, incoming-number, webhook, or WebRTC workflows in this repository. Covers AMIEWeb and Salesforce account separation, safe configuration correction, efficient API usage, LAB-first validation, and the required commit/push workflow."
---

# Twilio CUCM Workflow

## Account separation

Treat AMIEWeb and Salesforce as independent Twilio integrations. Never apply one account's configuration, webhook URL, Messaging Service, or TwiML App to the other account.

### AMIEWeb

- Account/subaccount: `AMNOne-Notification-PROD`.
- Approved inbound SMS URL: `https://api.amnhealthcare.io/listener/notification/v1/twilio/listener`.
- Compare and correct the number-specific `SmsUrl`/`SmsMethod` configuration.
- Use the AMIEWeb Messaging Service configuration already defined in the application.

### Salesforce

- Account/subaccount: `Enterprise Org Prod`.
- Messaging Service: `1-1 Communication Msg Service`.
- TwiML App name: `AssociateNumberWithFuncitonURL`.
- TwiML App SID: `APe224cb06b566df112639cdb4539f70b2`.
- The spelling `Funciton` is intentional because it matches the Salesforce Twilio account.
- Do not apply the AMIEWeb SMS URL or AMIEWeb Messaging Service.
- Do not add a reset action. If the current Messaging Service is wrong, move the number directly to the required service.

## Performance rules

- Avoid AXL N+1 calls. Batch CUCM data with `executeSQLQuery` and build local indexes.
- Reuse Twilio number and Messaging Service caches for read-only pages.
- Invalidate caches only after successful mutations or explicit refresh requests.
- Cache valid Genesys OAuth tokens until shortly before expiry; never cache failed token requests.
- For Genesys WebRTC batches, load phone inventory once and reuse an in-memory index across users.
- Preserve pagination and endpoint fallbacks unless representative payload tests prove they are unnecessary.

## UI and routing

- Preserve existing Page 3 panel IDs and routes when renaming menu items.
- Keep dedicated pages visually consistent with the first Page 3/Twilio lookup item.
- Use explicit full/partial number lookup and load controls for dedicated number pages.
- Correctly configured rows should show `Correct` and `No action needed`; do not render a correction button for them.
- Only render correction actions when a real mismatch exists.

## Safety and validation

- Work LAB-first. Do not change PROD behavior without LAB validation.
- Keep corrections narrowly scoped to the selected Twilio subaccount and phone SID.
- Never log or expose Twilio auth tokens, passwords, or other secrets.
- Validate with `python -m py_compile main.py` and `git diff --check`.
- For behavior changes, add or run focused tests/mock call-count checks where available.
- After every requested code change, commit and push automatically; verify `HEAD` matches `origin/main` before giving deployment instructions.
- Provide the LAB pull/restart command after a verified push:

```bash
cd /opt/cucm-web && git pull origin main && sudo systemctl restart cucm-web && sudo systemctl status cucm-web --no-pager
```

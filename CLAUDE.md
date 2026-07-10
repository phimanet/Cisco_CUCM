# Cisco CUCM Project Tracker

This file is the single source of truth for ongoing goals, pending tasks, and key decisions across our conversations.

## Last Updated
- Date: 2026-07-02
- Updated by: GitHub Copilot

## Active Goals
- Establish and maintain a centralized, continuously updated project tracker in this file.
- Maintain current working FastAPI web portal that executes imported CUCM automation scripts.
- Migrate external access from HTTP to HTTPS on Ubuntu Server 24.04.
- Keep service internal-only with no internet exposure.

## Pending Tasks
- [ ] Define internal certificate renewal/rotation procedure and owner.
- [ ] Confirm internal subnet allow-list for UFW/Nginx access control.
- [ ] Document deployment/runtime prerequisites (Python env, FastAPI/Uvicorn, network access to CUCM/Unity).
- [x] Centralize environment-specific values — AD LDAP config deployed via `/opt/cucm-web/.env` + systemd EnvironmentFile on both LAB and PROD.
- [ ] Add lightweight health check and structured error responses for web routes.
- [ ] Add minimal regression tests for toolkit functions that generate CSV outputs.

## Enhancement Backlog
- [x] [P1][Done] Person Lookup by name — search CUCM end users by last name + optional first name; returns extension, email, and all associated devices with type labels (CSF/TCT/BOT). First item on the menu, inline table results.


- [x] [P1][Done] Convert HTTP to HTTPS using internally signed enterprise certificate, with Nginx TLS termination and HTTP -> HTTPS redirect.
- [x] [P1][Done] Add input validation and user-friendly error display on all web forms.
- [ ] [P1][Idea] Add reusable environment/config file for CUCM/Unity hosts, partitions, and defaults.
- [ ] [P1][In Progress] Remediate Ubuntu 24.04 vulnerabilities and clean up host hardening findings (SNOW TASK0723797).
  - [x] CVE-2024-6387 (CVSSv3 8.1) — OpenSSH patched to 9.6p1-3ubuntu13.16 ✓
  - [ ] FTP unencrypted (CVSSv3 7.5) — vsftpd stopped; blocked on Sean Beavers identifying 10.241.17.165 before disabling
  - [ ] SSH Weak MACs (CVSSv3 7.5) — umac-64 removed; next step is controlled removal test of hmac-sha1-etm and hmac-sha1 to verify Cisco systems negotiate stronger MACs
  - [ ] CVE-2025-61984 (CVSSv3 3.6) — Not started
- [x] [P1][Done] Offboard (Separate Employee) workflow now auto-releases toll-free translation pattern: searches description for First Last name + verifies Called Party Transform Mask matches removed extension; if found, sets description to "{pattern} Available" and resets mask to 2481001. Skips silently if no match found.
- [ ] [P1][Planned] v1.01 enhancement: add VeraSMART (Calero on-prem) LAB-only automation module scaffold in portal (queue intake, run status, audit/log placeholders; no production rollout yet).
- [ ] [P1][Planned] On Jabber build workflows (Page 1 and Page 2), detect Unity voicemail failure due to AD inactive account, prompt admin for start date, auto-schedule voicemail creation for that user at 10:00 AM PST on start date, then email the build operator on success (operator email derived from username with trailing `.ad`/`.adm` removed + `@amnhealthcare.com`).
- [ ] [P1][In Progress] Twilio AMIEWeb SMS-only hosting workflow on Page 3: supports one or more numbers, updates SMS webhook fields only (no voice changes), LAB validated for panel visibility and awaiting operator-provided POST endpoint values for live update test.
- [x] [P1][Done] Block Inbound Calls by Caller ID Number workflow delivered and validated in PROD: template-driven translation pattern create/lookup/list/delete, normalized 10-digit display (71 prefix removed), auto-date on create, delete confirmation, explicit "Block Not Found" messaging, and availability on both Page 2 and Page 1 (bottom menu).
- [x] [P2][Done] After job submission, clear the "User ID for person..." input field to prevent accidental repeat Jabber creation.
- [x] [P2][Done] Refresh the web portal theme to align with AMN Healthcare visual style (brand colors, typography, spacing, and overall look/feel).
- [x] [P2][Done] Add per-option success/failure summary panel in the UI after CSV generation.
- [ ] [P2][Idea] Add a lightweight audit trail (who ran what option and when) for internal operations.
- [ ] [P2][In Progress] SIP Call Search LAB page and UDP listener for CUBE `debug ccsip messages` ingestion, with source tagging for Las Vegas `las-voip-rtr` and Reno `RNOVOIPRT01`, 15 MB per-file rotation, and total-size cap setting.
- [ ] [P2][Idea] Add call-record explorer page with filters for extension/calling/called number, datetime range, call length, username/device name, and SIP message/call trace retrieval in the same workflow.
- [ ] [P3][Idea] Add optional dry-run mode for high-impact actions before execution.

Status keys:
- `[Idea]` captured but not planned
- `[Planned]` approved and queued
- `[In Progress]` currently being implemented
- `[Done]` completed and validated

Priority keys:
- `[P1]` high impact / urgent
- `[P2]` medium priority
- `[P3]` low priority / nice to have

## In Progress
- Baseline analysis of `main.py` and `toolkit/` completed; preparing hardening roadmap without changing current behavior.
- Drafted Ubuntu 24.04 HTTPS migration runbook for this project.
- HTTPS migration target host confirmed: `lascrtmp01.ahs.int` (DNS already working).
- Ubuntu server IP confirmed: `10.241.18.15`.
- SIP Call Search is now LAB-only and hidden from PROD navigation; next step is LAB restart and CUBE syslog validation.

## Completed Tasks
- [x] Created central project tracking structure in `CLAUDE.md`.
- [x] Confirmed current scripts and pages are working as baseline behavior.
- [x] Completed HTTPS cutover with internally signed enterprise certificate, Nginx TLS termination, and HTTP -> HTTPS redirect.

## Key Decisions
- 2026-04-30: Use `CLAUDE.md` as the canonical running log for goals, pending tasks, and key decisions for this repository.
- 2026-04-30: Treat current `main.py` routes and `toolkit/` scripts as the stable working baseline.
- 2026-04-30: Prioritize reliability and maintainability improvements next, while preserving existing workflow behavior.
- 2026-04-30: Standardize production exposure as HTTPS via Nginx, with Uvicorn bound to localhost only.
- 2026-04-30: Use internally signed enterprise certificate for Ubuntu production TLS cutover.
- 2026-04-30: Environment remains internal-network only; no internet exposure planned.

## Known Configuration
- TLS is used for CUCM/Unity API traffic (`https://<host>:8443/axl/` for AXL).
- Python `requests` certificate verification is intentionally disabled in current toolkit sessions (`verify=False`) to preserve compatibility with existing CUCM/Unity certificate trust state.
- Decision on 2026-05-01: Do not change `verify=False` yet; revisit after controlled internal CA trust-chain validation to avoid breaking current automation workflows.

## Open Questions
- Which immediate deliverable should be prioritized first in this repository?
- `10.241.17.165`: Unknown FTP client connecting to vsftpd — asked Sean Beavers to identify; suspected networking device sending backups. Pending confirmation on whether it can switch to SFTP.

## Conversation Notes
- Keep this section concise with short chronological notes after significant updates.

### 2026-06-19
- Added portal version labeling in UI: current web pages marked as v1.0; queued enhancement marker for v1.01 (VeraSMART automation).
- Added Administrative Items LAB-only v1.01 scaffold panel: VeraSMART queue CSV template download, queue upload endpoint, and run-status view placeholders.
- Confirmed rollout posture: LAB web server only for v1.01 testing; no production pull/deploy during this phase.
- Captured next priority enhancement as Planned: automatic deferred voicemail build at 10:00 AM PST after AD-inactive Unity failure, with operator-success notification email.

### 2026-06-23
- Completed Unity SSL consistency remediation for remaining flows and promoted fix commit `13b9c84`.
- Added/validated Page 2 CUCM LDAP sync trigger behavior (auto-select LAB/PROD agreement by host) and moved menu item to bottom.
- Validated production workflows end-to-end after pull/restart: Separation, Jabber Build, Name Change, and Reset Voicemail PIN (all success).
- Confirmed Twilio AMIEWeb workflow still passes after promotion.
- Confirmed LAB and PROD parity: both servers on commit `13b9c84` with `cucm-web.service` active/running.

### 2026-06-24
- Strike Mask troubleshooting resumed for PROD mismatch where available patterns were not being returned in Page 2.
- Confirmed runtime has no `STRIKE_MASK_*` overrides loaded from `.env` on PROD; app used in-code defaults for Strike Mask matching.
- Updated Strike Mask availability logic to remove prefix dependency and use global translation pattern search with rule-based filtering.
- Final rule confirmed: available Strike Mask translation patterns must have description beginning with `Strike Mask -` and Called Party Transform Mask exactly `2481001`.
- Updated Strike Mask apply/reverse/template paths to consistently use `2481001` for available-state mask handling.
- Git operation on local Windows workspace hit repeated interactive prompt (`Deletion of directory '.git/objects/*' failed. Should I try again?`), causing commit/push flow interruption during this session.
- Enabled SMS Number Lookup menu item and route behavior for PROD using `SMS_NUMBER_LOOKUP_ENABLED` feature flag defaulting to enabled.
- Added new Page 3 function: **Twilio SMS Hosting - AMIEWeb** with bulk number input and backend route `/twilio/amieweb/sms-host`.
- SMS Hosting route now requires: phone number(s), `sms_url` (HTTPS), and `sms_method` (`POST`/`GET`); optional fallback/status-callback fields supported.
- Confirmed implementation intent: SMS-only update path modifies Twilio IncomingPhoneNumber messaging webhooks and does not alter voice webhook settings.
- Current operator workflow paused at input collection stage: POST confirmed; awaiting final SMS URL and first test number for live run.
- Operator provided SMS POST endpoint for Twilio hosting: `https://api.amnhealthcare.io/listener/notification/v1/twilio/listener`.
- Session paused for workstation reboot before collecting first target number and running SMS-hosting test.
- Twilio Hosted Numbers API path validated against Twilio docs; confirmed service is in Developer Preview and currently blocked in this account context (resource-not-found/auth mix from Twilio endpoints).
- Added clear product hold-state in UI and backend guard: **Twilio SMS Hosting - AMIEWeb (Developer Preview - NOT ACTIVE YET)** with feature flag `TWILIO_HOSTED_NUMBERS_ACTIVE` defaulting to disabled.
- Standardized hosted-number failure messaging to concise entitlement/auth guidance instead of verbose endpoint dump.
- Added Twilio SMS hosting audit retention control with automatic prune to **90 days** (`TWILIO_SMS_HOSTING_AUDIT_RETENTION_DAYS`, default 90) on append/read/download paths.
- Baseline freeze decision: keep current implementation in LAB/PROD as prepared-but-disabled foundation until Twilio enables preview access.

### 2026-07-02
- Added new LAB-only SIP Call Search page as a separate post-login route (`/sip-call-search`) with settings-controlled UDP listener on port 1024, raw file rotation, retention cleanup, and search filters for Call-ID, source cube, numbers, method, and response code.
- Updated SIP Call Search exposure so PROD hides the link and endpoint returns not found, while LAB continues to show the page.
- Updated SIP capture/search to store each UDP payload as a full SIP message (instead of per-line fragments) so result details display complete message content for new records.
- Added SIP capture file download support in LAB page (list + direct download for raw `.log` and parsed `.jsonl` files) to aid deeper troubleshooting.
- Search results now include a Capture File column/header showing the originating file path per record for faster file pinpoint and download.
- Capture File display is now compact in results (filename only) while preserving full-path link target for download.
- Added legacy-record fallback matching so older line-based records attempt to resolve and display a downloadable raw file path when possible.
- Added legacy SIP block reconstruction using `Received:` / `Sent:` boundaries so older line-based rows can be grouped into whole-message output and de-duplicated by message block.
- Adjusted SIP search performance mode: deep legacy reconstruction is now opt-in from UI (default fast mode) to avoid gateway timeouts on normal searches.
- Refined SIP search mode to hybrid behavior: filtered searches auto-reconstruct a small number of legacy rows for better Raw output, while Deep Legacy Parse remains opt-in for broad reconstruction.
- Normalized SIP search fields: Call-ID now displays token before `@`, and From/To columns now extract SIP user digits (avoiding extra digits from IP/tag metadata).
- Updated SIP search Received column formatting to show concise date+time (`YYYY-MM-DD HH:MM:SS.ffffff`) without timezone suffix for easier scanning.
- Added on-demand SIP ladder generation by Call-ID in LAB search page, returning Mermaid sequence diagram text from matched flow events.
- Updated SIP Call Search layout to move listener/status summary cards into the top header and removed the Authenticated Operator card to conserve vertical space.
- Further compressed SIP header layout: removed Last Record tile, slimmed remaining status tiles, removed SIP intro panel, and renamed filter panel title to "SIP Call Search - Search Filters".
- Updated SIP top header layout so Listener Status / Total Stored / Files render on the same top row as the environment banner/navigation when screen width allows, with responsive wrap fallback on smaller screens.
- Repositioned SIP header status tiles to the middle region of the top row, immediately left of the environment banner/navigation controls, to preserve search viewport space.
- Restyled SIP top header to match Page 1 visual language (AMN dual-gradient bar, shadow/border treatment, AMN brand fallback text, and Page 1-style action buttons/colors).
- Adjusted SIP middle status cards to compact single-line pills with 32px height so they visually align with the Production/LAB environment pill height in the top header.
- Corrected header title scoping: "Voice Operations Portal - SIP Call Search" now appears only on the SIP Call Search page; Main/Administrative pages reverted to "Voice Operations Portal".
- Improved legacy SIP reconstruction for Reno-style syslog lines: when `Received:`/`Sent:` markers are absent, parser now groups contiguous lines by shared syslog message ID to rebuild full SIP message blocks and normalize result formatting.
- Search/reconstruction fallback broadened to all source folders for the same day when source-key scoped lookup misses, so parsing/formatting fixes apply across all SIP log files (not router-specific only).
- Legacy reconstruction trigger expanded: search now reconstructs partial single-line legacy `raw_message` rows (not only blank messages), improving Reno line-based output consistency.
- Added `Direction` field extraction (`Received`/`Sent`) from SIP message content and surfaced a new Direction column in SIP search results (positioned before Method).
- Direction column now includes Via endpoint context, rendering labels like `Received from 10.141.18.11:5060` / `Sent from 206.147.150.91:5060` to identify call flow origin quickly.
- Direction wording refined so Sent entries read `Sent to <via-endpoint>` while Received remains `Received from <via-endpoint>`.
- Direction endpoint display now trims default SIP port suffix `:5060` for cleaner labels (for example, `Sent to 10.141.18.11`).
- SIP search Call-ID column now formats IDs into two-line segments (split after the second hyphen group) to reduce horizontal pressure and improve table readability.
- Direction column now uses two-line formatting: line 1 shows `Sent to` or `Received from`, line 2 shows the Via endpoint IP for improved table compactness.
- Updated SIP search Received column formatting to show concise date+time (`YYYY-MM-DD HH:MM:SS.ffffff`) without timezone suffix for easier scanning.
- SIP Call-ID search now normalizes pasted values by converting whitespace to hyphens (for wrapped two-line IDs), so copied table values still match search results.
- SIP search results table now places the Capture File column at the far right (last position) to match operator preference.
- SIP results table column widths compacted (Received/Source/Method/Response/From/To/Capture narrowed) and Raw preview width increased to maximize horizontal space for message inspection.
- SIP search date/time inputs now default to today (`00:00` start, `23:59` end) on initial page load when blank, while remaining fully editable for custom ranges.
- Fixed SIP page bad-gateway regression: corrected JavaScript function brace escaping inside Python f-string template so app startup no longer fails.
- Hardened Received timestamp display normalization so timezone suffixes like `-07:00`/`Z` are trimmed reliably across parse/fallback paths.
- Added server-side `received_at_display` formatting (timezone removed) and wired SIP results table to use it first, eliminating client-side timezone suffix drift.
- Added structured SIP ladder payload (participants + events) and replaced the Mermaid-only preview with an inline SVG ladder diagram while retaining Mermaid source as an expandable fallback.
- Repaired SVG ladder backend helper after refactor so ladder API again returns the expected Mermaid + participants + events payload without runtime failure.
- Cleared remaining bad-gateway startup corruption by removing stray ladder helper fragments accidentally pasted into the top constants section and `_git_commit_short()`, restoring successful Python compilation.
- Removed an additional stray menu-template artifact (`+` line in Page 1 HTML) and restored the canonical structured ladder helper definitions to eliminate remaining runtime corruption.
- Fixed post-reboot login 500 (`NameError: _CREDENTIAL_CIPHER`) by restoring safe credential-cipher initialization with plaintext fallback when `CUCM_WEB_CREDENTIAL_FERNET_KEY` is unset/invalid.
- Updated SIP Call Search and ladder workflow to support dual correlation keys: Cisco-GUID (recommended primary) plus optional Call-ID search/filter compatibility.
- Improved Cisco-GUID search robustness: pasted wrapped values are now canonicalized to 4x10-digit GUID format, and legacy indexed SIP rows now derive missing Cisco-GUID/Call-ID from raw message content before filters are applied.
- Updated SIP capture file browser defaults to show only the latest 5 files, and added optional modified-time Start/End datetime range filters plus adjustable file-list limit for targeted download windows.
- Optimized SIP search filter path to avoid deriving Cisco-GUID/Call-ID from every indexed row unless those specific filters are requested, reducing risk of Nginx 504 timeouts on normal digit/date searches.
- Source tagging expanded to include Ribbon SBC IPs: Las Vegas `10.241.16.217` mapped to `las-voip-rtr`, and Reno `10.141.16.40` mapped to `RNOVOIPRT01` for consistent SIP source labels.
- Added dedicated SIP source filters for Ribbon SBC endpoints: Las Vegas Ribbon SBC (`10.241.16.217`) and Reno Ribbon SBC (`10.141.16.40`) now selectable independently from CUBE filters.
- Observed Las Vegas Ribbon feed arriving with source `10.241.18.217`; added mapping to Las Vegas Ribbon SBC filter key so records are not tagged as unknown.
- Added Reno Ribbon alternate source mapping (`10.141.18.40`) to Reno Ribbon SBC filter key for parity with observed Las Vegas alternate-source behavior.
- Improved legacy SIP reconstruction for Reno-style syslog lines: when `Received:`/`Sent:` markers are absent, parser now groups MSGID-anchored Ribbon blocks and extracts SIP payload lines until next prefixed syslog entry.
- Direction parsing now uses pattern-based Ribbon metadata rules (for example `Received message ... from [...]` and `sending from ... to [...]`) so Sent/Received extraction does not depend on fixed line offsets.
- Refined Ribbon direction parsing to preserve metadata preamble lines during MSGID reconstruction and apply a deterministic fallback from the line three rows above SIP Method (for example `tlDataReceived:Received message ... from [IP]`) so Direction reliably renders `Received from IP` / `Sent to IP`.
- Updated SIP Show/Raw reconstruction for MSGID blocks to always include at least the three lines above the SIP start line (plus earlier detected Ribbon metadata lines), so operators can see preamble context directly in the results window.
- Mitigated SIP search 504 risk by pruning index-day scans to the requested Start/End date window before reading JSONL records, reducing backend work for narrow time-range queries.
- Fixed direction gap observed in live Reno results: search now forces legacy enrichment for Ribbon rows when Direction is blank and applies metadata-text fallback (`sending from ... to ...` / `Received message ... from ...`) before returning records.
- Increased SIP Show/Raw reconstructed preamble window from 3 to 7 lines above SIP method to improve operator-assisted direction validation in live traces.
- Direction inference now uses a proximity search window of up to 7 lines above and 7 lines below SIP method/status line, selecting the nearest Ribbon send/receive metadata marker when available.
- Proximity-window line counting refined to use physical lines (blank lines included) around SIP method/status so offset-based matching aligns with operator-visible Show output.
- Expanded direction/search fallback window to up to 10 lines above and 10 lines below SIP method/status, and increased Show/Raw preamble baseline to 10 lines above SIP start for broader edge-case visibility.
- Fixed MSGID reconstruction window to include up to 10 physical lines *before* MSGID from source logs, so Show now displays true pre-INVITE context and Direction fallback can see upstream Ribbon metadata.
- Added fast raw-line prefilters (ANI/digits, method, response code, source key, quick received_at guard) before JSON decode in SIP search loop to reduce CPU load and mitigate 504 timeouts on large day indexes.
- Validation checkpoint (pause state): current objective is end-to-end traceability confirmation for inbound call flow **through Cisco CUBE -> Ribbon SBC -> outbound carrier leg** using SIP Call Search Direction + Raw preamble context.
- Current validated parser findings from real LV/Reno Ribbon samples:
  - Receive marker: `tlDataReceived:Received message on [...] from [...]` (and `Incoming message on [...] from [...]`).
  - Send marker: `sending from [...] to [...]`.
  - Typical offsets from SIP start observed in uploaded logs: receive near `-6` lines, send near `-4` lines, with rare outliers.
- Next resume step: run live validation searches by call sample and confirm both `Received from <ip>` and `Sent to <ip>` appear consistently across CUBE/Ribbon transition legs.
- User-approved next feature (queued for next session): add deterministic **Call Group ID** to correlate one real call across multiple SIP legs (CUBE internal/external + Ribbon internal/external) and make troubleshooting timeline easier to follow.
- Approved behavior for upcoming implementation:
  - Generate stable Call Group ID from ANI + start-time bucket + strongest available identifiers (Cisco-GUID, GCID, Call-ID family) + peer handoff signature.
  - Display Call Group ID in search results and enable quick filter to isolate one full call group.
  - Keep individual SIP legs visible while sharing the same group ID for parent-call tracing.
- Session handoff note: user paused work for today and requested immediate coding continuation on next open, starting with Call Group ID implementation.
- Implemented deterministic `Call Group ID` assignment in SIP search results using ANI + start-time bucket + strongest available identifiers (Cisco-GUID/Call-ID) + direction/source signature so one real call can be traced across multiple legs.
- Added `Call Group ID` column in SIP search results table for quick full-call correlation.
- Added quick search-time controls in SIP Call Search: selectable recent window with button to set Start/End to last N minutes (default Last 10 Minutes) for fast test-call lookups.
- Fixed SIP listener auto-start on app boot by wiring startup background services into FastAPI startup event so UDP 1024 binding survives service restarts.
- Source tagging configured for Las Vegas CUBE (`las-voip-rtr` / `10.241.255.3`) and Reno CUBE (`RNOVOIPRT01` / `10.141.255.13`).
- Genesys Admin extraction enhanced with downloadable raw payload artifact per run: UI now provides a **Download Raw Genesys JSON** link sourced from `/download/job-output/{job_id}` for full payload parsing.
- Genesys WebRTC Phone mapping updated to use configured station values directly (routing status station name first, user profile station fallback) instead of requiring a strict WebRTC name match.
- Genesys WebRTC Phone mapping now adds explicit `/api/v2/users/{id}/stationassociations` fallback so assigned stations are captured even when routing status/profile payloads omit station fields.
- Added secondary Genesys fallback to query Phone Management inventory (`/api/v2/telephony/providers/edges/phones`) and map phone name to the user when station-association API is unavailable (observed 404 in current org).
- Refined Phone Management matching logic to support org payloads where phone entities omit explicit owner fields; extractor now uses exact normalized phone-name == user-name fallback (e.g., "Michael Beecher").
- Updated Phone Management fallback matching to treat display-name fields (`displayName`, `stationName`, `phoneName`) as equivalent match candidates to `name`, aligned to WebRTC build naming convention.
- Added persistent WebRTC template baseline file at `toolkit/genesys_webrtc_phone_template.json` (seeded from Michael Beecher phone) so future builds can use template IDs even if source user lookup is unavailable.
- Genesys extraction table now surfaces template-ready fields per user: template source, template phone name, site ID, base settings ID, and line count.
- Added inline Genesys action flow: when lookup shows no WebRTC phone, UI now offers **Build + Associate** button per user.
- Added backend route `/genesys/users/build-webrtc` using template baseline + Genesys Phone Management creation path; attempts user association during create and falls back to station association call when needed.
- Fixed Genesys extractor parsing for ACD skills where payload returns `entities[].name` directly (not only `entities[].skill.name`), and changed ACD Skills/Queues display to explicit `(none)` when empty to avoid blank-column confusion.
- Refined Genesys Phone Management lookup paging depth with configurable cap (`GENESYS_PHONE_LOOKUP_MAX_PAGES`, default 50) so existing users like Shane Carr are not missed when inventory spans many pages.
- Added queue fallback extraction path: when `/api/v2/users/{id}/queues` returns empty, extractor now checks queue membership via `/api/v2/routing/queues` + `/api/v2/routing/queues/{queueId}/members` to capture real queue assignments (supports multi-queue users).
- Added priority queue membership probe support (`GENESYS_PRIORITY_QUEUE_IDS`, seeded with `df95c0ce-1ca4-4ab1-8ce3-f474642edf4d`) so known queues are checked first for user membership when direct queue listing is empty.
- Raw Genesys extract output now includes `resolved_queues` and `queue_resolution_source` so queue fallback behavior can be verified even when direct `/users/{id}/queues` payload is empty.
- Added new Page 3 function: queue lookup by queue name/ID in Genesys Admin; returns matched queues and member roster so queue membership can be validated directly.
- Queue lookup now treats queue ID from real-world input (including full Genesys URL strings) as primary key; route extracts UUID and queries members directly before any name search.
- Queue membership retrieval now uses multi-endpoint fallback (`/members`, `/members?expand=user`, `/users`) with per-strategy page diagnostics surfaced in the UI and response payload.
- Queue-based user extraction fallback now reuses the same queue-members helper so membership checks benefit from identical endpoint fallback behavior.

### 2026-07-07
- Fixed SIP Call Search browser-to-server time-window mismatch: `datetime-local` search/file filter values are now serialized to timezone-aware ISO timestamps before request submission, preventing recent-call searches from missing records when operator timezone differs from the Ubuntu server timezone.
- Expanded SIP ANI/DNIS extraction and filter fallback for inbound call search: `From Digits` / `To Digits` now consider alternate SIP identity headers (`P-Asserted-Identity`, `Remote-Party-ID`, `P-Preferred-Identity`, `Diversion`, `History-Info`, request URI) and can match against raw SIP message content when older indexed rows have incomplete parsed digit fields.
- Hardened SIP search UX for operator input patterns: a digits-only value entered in the `Call-ID` field is now treated as a caller/called number fallback match, and the UI placeholder/status text now advertise that behavior to reduce false-zero searches.
- Fixed legacy CUBE line parsing for SIP search: header extraction now strips syslog debug prefixes before matching `From:`, `To:`, `Call-ID:`, and related SIP headers, allowing older single-line indexed records to match ANI/DNIS/Call-ID searches (validated against raw `6194104147` call block at `2026-07-07 13:33:44 PST`).
- Added raw capture fallback search path for SIP lookups: when JSONL index search returns zero for a filtered query, the backend now scans raw `ccsipDisplayMsg` blocks directly and parses matching calls from `.log` capture files, covering cases where real call evidence exists in raw capture but the index is incomplete/stale.
- Mitigated SIP search 504 risk by streaming JSONL index shards and raw capture blocks instead of bulk-loading multi-GB files into memory, allowing time-limit checks to interrupt long searches before Nginx times out.
- Fixed recent-call raw fallback ordering: raw SIP capture scans now process newest `.log` parts first, so narrow windows like `Last 5 Minutes` reach the latest call blocks before exhausting the search time budget on older files.
- Extended recent-call raw fallback to Ribbon SBC traces: fallback block detection now recognizes Ribbon `MSGID` packets and parses bracketed Ribbon timestamps, so searches can return both Cisco CUBE and Ribbon SBC legs for the same fresh call path.
- Refined Ribbon raw fallback block boundaries: Ribbon `MSGID` groups now remain contiguous until the next block start, preventing premature block splits that could hide traversed Ribbon SBC call legs in recent searches.

### 2026-07-08
- Enhanced Build User DN Type labels on Main Operations Build Cisco Jabber form to show dynamic area-code context from DN Prefix Settings: `Recruiter (prefix)`, `General Employee (prefix)`, and `Strike Employee (prefix)`. Labels now update automatically as DN Prefix Settings change.
- Added new SMS Item Menu function (AMIEWeb-only): **Twilio Hosting Status - Ready to Verify Ownership**. This queries Twilio Hosted Number Orders and returns rows currently in Ready-to-Verify status, with optional direct phone filter support (example: `+14697061956`) and table columns for phone number, friendly name, capabilities, status, and order SID.

### 2026-07-09
- Hardened Aerialink lookup flow used by SMS Item Menu (Aerialink SMS-AMIEClassic panel and shared SMS lookup): preflight now treats HTTP `400/422` as endpoint reachable (query-shape mismatch) instead of hard-fail, and runtime lookup now retries multiple request patterns (`codes`, `code`, `phoneNumber`, `number`, `msisdn`, and path-style `/codes/{digits}`) before declaring not provisioned.
- Added repository-level script-change lock guard: new `.githooks/pre-commit` blocks commits touching `main.py`, `toolkit/*`, and `scripts/*` unless explicit override env var `ALLOW_PROTECTED_SCRIPT_CHANGES=1` is set. Added enable helpers at `scripts/enable_protected_script_lock.sh` and `scripts/enable_protected_script_lock.ps1`.
- Added new Page 2 panel **Hunt List Members** above existing Update Hunt List Line Group menu item: supports hunt-list search/selection using the same line-group search pattern and lists current member extensions with resolved owner name (display name/owner ID fallback, plus line alerting-name fallback), with inline table output.
- Added new Page 2 read-only panel **Security Group Identifier (Read-Only)** to verify AD group identity for `AzAppReg_CiscoUnity-PROD_EmailIntegration`, returning Name, SamAccountName, DistinguishedName, ObjectGUID, SID, GroupCategory, and GroupScope without modifying memberships.
- Verified read-only security-group identity for future enhancement lock: Name/SamAccountName `AzAppReg_CiscoUnity-PROD_EmailIntegration`, DistinguishedName `CN=AzAppReg_CiscoUnity-PROD_EmailIntegration,OU=Distribution Groups,OU=Corp,DC=ahs,DC=int`, ObjectGUID `03cde812-4279-4c3e-a0d6-704ed5843bf6`, GroupCategory `Security`, GroupScope `Universal`.
- Decision confirmed: do **not** modify the current working AD phone update workflow (`telephoneNumber`/`ipPhone`) at this time; keep enhancement implementation deferred until explicitly approved.
- Future enhancement requirement captured: when approved for coding, Build Cisco Jabber flow should add user to the fixed security group (`AzAppReg_CiscoUnity-PROD_EmailIntegration`) after AD phone update, and Separation workflow should remove user from that same security group after AD phone fields are cleared.

### 2026-07-10
- Added new Page 2 function **Check Unifed Messaging Security Group** with a fixed group target (`AzAppReg_CiscoUnity-PROD_EmailIntegration`) and per-user actions to check membership, add member, or remove member using AD User ID (`samAccountName`).
- Added backend route `/admin/ad-group-membership` and toolkit helper `manage_ad_group_membership(...)` with PowerShell ActiveDirectory path plus LDAP fallback so membership validation/mutation can run on both Windows-style and Ubuntu LDAP environments.
- Added UI result summary table for each membership action showing final membership state, changed/not-changed state, user/group DNs, and backend source (`powershell` or `ldap`) to support proof-of-control before wiring into Jabber Build/Separation workflows.
- Removed repeated CUCM username/password prompts from Menu and Administrative menu workflows by switching affected forms to hidden cached-session CUCM fields (`cucm_host`, `cucm_user`, `cucm_pass`) so operators are not asked to re-enter credentials during normal session use.
- Updated AD group membership helper fallback chain to include `ldapsearch` + `ldapmodify` path when both PowerShell and Python `ldap3` are unavailable, aligning behavior with Linux-host-compatible AD tooling expectations.
- Removed visible Unity Admin username/password fields from Menu -> Reset Unity Voicemail PIN panel and switched that workflow to hidden cached-session Unity credentials (`unity_user`, `unity_pass`) for consistent no-reprompt behavior.
- Fixed Start Here action-button reliability for person/extension lookup tables by replacing inline `onclick` prefill buttons with data-attribute click bindings; this resolves intermittent no-op behavior reported on **Build Android** (Option 4 prefill).
- Hardened Start Here prefill action buttons (Build Jabber/iPhone/Android, Reset PIN, Name Update) with direct DOM fallback panel-switch/prefill logic when global prefill helper is unavailable, addressing full no-op behavior while keeping email resend actions unchanged.
- Fixed **Remove only Jabber Mobile** search on both Menu and Administrative pages: form submission is now explicitly JS-driven (no native page submit fallback), preventing unwanted redirect to Start Here and restoring search execution on button click.
- Hardened mobile-delete search inline hooks for browser compatibility by removing dependence on inline `event` object and adding explicit missing-handler status messaging if JS does not load.
- Added panel-local fallback script in Menu -> Remove only Jabber Mobile so `runMenuMobileDeleteSearch` and delete actions are defined directly at panel render time, preventing no-op search when downstream script registration is skipped.
- Expanded AD phone-field update fallback chain used by Option 11 to include `ldapsearch` lookup + `ldapmodify` attribute update/clear path when both PowerShell and Python `ldap3` are unavailable, aligning behavior with Linux-host AD tooling environments.
- Added panel-local action handler for Menu -> Block Inbound Calls by Caller ID Number so Block/Lookup/List/Delete actions execute via inline-safe JS hooks and no longer fall back to Start Here when downstream script registration is skipped.
- Added support for optional LDAP service-account bind overrides (`AD_LDAP_BIND_USER` + `AD_LDAP_BIND_PASSWORD`) for AD update/group LDAP paths, and improved Option 11 failure detail for LDAP insufficient-access (`LDAP 50`) to explicitly indicate delegated write rights are required.
- Hardened Build User CSF Phone run button handler to execute even if shared duplicate-device precheck helper is unavailable, preventing no-op behavior on button click.
- Added offboard action-button prefill fallback between Admin search and Main Offboard panel using sessionStorage handoff (`menu_prefill_panel` / `menu_prefill_target_user`) so selected usernames carry reliably into Separate Employee workflow.
- Added panel-local Offboard prefill hydration in the Offboard script (URL `target_user` + sessionStorage fallback) to guarantee target user population even when global menu prefill script does not run.

### 2026-06-25
- Fixed `/healthz` telemetry `git_commit` reporting with robust commit resolution fallback; commit `0c59386`.
- Verified LAB parity after pull/restart: `/healthz` now returns `git_commit":"0c59386"` and service is healthy.
- Confirmed prior 502 seen in parity output was startup timing noise (Nginx upstream connect refused during immediate post-restart probe), not runtime app failure.
- Hardened `scripts/check_env_parity.sh` health section with retry window (up to 20 seconds) before declaring health probe failure; commit `34f8757`.
- Promoted parity retry fix to LAB and PROD; both environments aligned on latest `main`.
- Added operator instruction convention: every operational step now starts by explicitly stating environment (LAB/PROD/BOTH).
- Created new local rollback checkpoint tag on both servers: `websave-2026-06-25`.

### 2026-07-01
- Completed and deployed inbound caller ID block enhancement updates: template-based block creation (no live-pattern cloning), normalized 10-digit lookup/list display, remove by 10-digit or 71-prefixed value, conditional delete actions only when blocked entry exists, and finalized UI text labels.
- Added the same **Block Inbound Calls by Caller ID Number** workflow to Page 1 (bottom of menu) to match Page 2 availability.
- Production validation confirmed by operator: deployed and tested in PROD; functions working as expected.

### 2026-06-16
- Added an in-app Action History page backed by the audit trail CSV, with recent activity summary cards and direct CSV download.
- Logged Send New Jabber Email actions into the audit trail so the history view includes inline notification activity.
- Enhanced the Jabber pre-check result to highlight duplicate Jabber and voicemail resources before building.

### 2026-05-01
- Decision update: proceed with a controlled test to remove `hmac-sha1` after removing `hmac-sha1-etm`, then validate Cisco CUCM/Unity systems negotiate stronger MACs; rollback if any SSH automation fails.
- TASK0723797: vsftpd log analysis showed two FTP clients: `10.241.18.11` (CUCM CDR uploads, confirmed) and `10.241.17.165` (unknown — suspected networking device sending backups).
- Reached out to Sean Beavers to identify `10.241.17.165` and assess whether it can migrate to SFTP.
- vsftpd remains stopped; CDR uploads from CUCM are not flowing until decision is made.
- SSH MAC hardening in progress: 1 of 4 weak MACs removed; 3 remaining (umac-64@openssh.com, hmac-sha1-etm@openssh.com, hmac-sha1); removing one at a time on user schedule.
- Validation: Cisco CER backup works after Weak MAC hardening change (pass).
- Confirmed CUCM AXL calls are sent to `https://...:8443/axl/` (TLS in transit); cert verification remains disabled by design (`verify=False`) and logged under Known Configuration.
- Production CUCM confirmed: `lascucmpp01.ahs.int` (10.241.18.11), System version: 15.0.1.12900-234.
- Production Unity Connection confirmed: `lascutyp01.ahs.int` (10.241.18.17), System version: 15.0.1.12900-43.
- LAB CUCM confirmed: `lascucmpl01.ahs.int` (10.241.18.200), System version: 15.0.1.14901-2.
- LAB Unity Connection confirmed: `lascutypl01.ahs.int` (10.241.18.202), System version: 15.0.1.13900-61.
- Terminology: CallManager = Cisco Unified Communications Manager (CUCM).
- UI enhancement implemented: target "User ID for person..." field now clears immediately after form submission on target-user workflows.
- UI enhancement implemented: client-side validation now shows friendly inline errors for required/format fields across menu forms.
- UI enhancement implemented: job routes now return a result page with a text output preview box and a CSV download link.

### 2026-05-21
- Option 9 (Build User CSF Phone) enhanced to accept optional AD credentials in the web form and attempt AD phone field update (`telephoneNumber`, `ipPhone`) after CUCM device/line provisioning.
- Option 10 (Offboard User) enhanced to accept optional AD credentials in the web form and attempt AD phone field clear (`telephoneNumber`, `ipPhone`) after CUCM/Unity decommission workflow.
- Added shared toolkit helper module for AD phone field operations via PowerShell ActiveDirectory module, with explicit CSV result rows for AD success/failure.
- Updated Option 9 and Option 10 authentication flow to reuse the same CUCM credentials for AD operations (single credential set for CUCM/Unity/AD in these workflows).
- Added Ubuntu-safe LDAP fallback in AD helper so Option 9/10 can update AD when PowerShell/ActiveDirectory cmdlets are not available on Linux hosts.

### 2026-05-21 (LAB VALIDATION COMPLETE)
- LAB LDAP Configuration Final: `AD_LDAP_SERVER=lasdc01.ahs.int`, `AD_LDAP_AUTH=simple` (NTLM has MD4 issues on Ubuntu 24.04; SIMPLE UPN auth works)
- Option 9 LAB Test: ✓ PASS - AD phone fields updated successfully for test user (Alfredo.Salcedo)
- Option 10 LAB Test: ✓ PASS - AD phone fields cleared successfully for test user
- CSV output rows confirmed working for both workflows ("Update AD Phone Fields" / "Clear AD Phone Fields" with Success/Failed status)
- Production Requirement: TCP 636 (LDAPS) must be open from lascrtmp01.ahs.int (10.241.18.15) to lasdc01.ahs.int for LDAP operations

### 2026-06-05
- Restored Called Name Change workflow from previously fixed revision (`fad817a`) after full revert sequence.
- Reinstated UI panel + inline execution path in `main.py` and backend route `/called-name-change`.
- Reinstated toolkit module `toolkit/called_name_change.py` with CSF/BOT/TCT phone description updates, line alerting/caller-ID updates, and Unity mailbox DisplayName/SMTP updates.
- Completed AMN visual refresh for Main Operations and Administrative Items pages (enhanced topbar, hero section, navigation cards, panel styling, and spacing) while preserving existing workflows.
- Added automatic mobile Jabber notification emails for Option 3/4/5 (TCT/BOT/STRIKE): sends from `noreply@amnhealthcare.com` to target user `mailid` on successful new device creation, with install/login instructions.

### 2026-06-06
- Added Page 2 translation-pattern template generator seeded from example prefix `3148984689`, with a CSV template that keeps route partition and transform mask the same while leaving translation pattern and description as editable values.

### 2026-06-16
- Fixed Page 1 "Start Here" Re-send Mobile Email button: changed from `onclick="prefillMobileJabberNotify()"` (navigated to form) to `data-mobile-resend-uid` with inline handler (sends immediately without navigation).
- Added checkmark + green background visual feedback to "Re-send Mobile Email" buttons across all search interfaces (Page 1 Start Here, Page 1 Extension Lookup, Page 2 Admin Person Search).
- Added checkmark + green background visual feedback to "Send New Jabber Email" buttons on both Page 1 and Page 2 person search results (matches Re-send Mobile Email UX pattern).
- Enforced critical workflow: always commit and push code immediately after file edits — verified with `git log` before instructing user to pull.

### 2026-06-11
- Added two new Page 2 specialized menu items: **Twilio-Inbound-Verificaton-Phimane** and **Twilio-Inbound-Verificaton-LauraA**.
  - Each targets only its own translation pattern by exact constant description (never touches other patterns).
  - Only the translation pattern field is changed; all other settings are untouched.
  - Apply button: sets pattern to any user-entered value; starts a server-side 5-minute auto-restore fail-safe timer.
  - Restore button: immediately reverts to the home pattern (8585236648 or 8583503289) and cancels the timer.
  - Repeated Apply resets the 5-minute timer; UI shows a live countdown.
- Added stable Page 2 URL aliases: `/page2`, `/menu2`, `/menu-admin` all serve the same Administrative Items page.
- Fixed admin page navigation loop: removed forced logout redirect from Page 2 when cached CUCM password was missing — this was the root cause of the login→Page1→click Administrative Items→login loop.
- Cleanup: removed all temporary auth fallback mechanisms (sid hint, shared session file, session-data cookie) added during troubleshooting, since the real fix was the single forced-logout removal.
- Compact search layout update: converted Page 1 and Page 2 last-name lookup panels to inline label/input rows and shrank search box widths to reclaim vertical space.
- Updated New Cisco Jabber build notification email template to AMN welcome format, using the dynamically assigned/created number and the updated SharePoint training link.
- Updated New Cisco Jabber build email to send an HTML hyperlink for "How to use Cisco Jabber Softphone" (while preserving plain-text fallback content).

### 2026-04-30
- Initialized project tracker format.
- Confirmed workspace purpose: website front end that executes manually imported, working Python CUCM scripts.
- Completed end-to-end code analysis from `main.py` through all modules under `toolkit/`.
- Added Ubuntu 24.04 HTTPS deployment runbook for migration execution.
- Updated HTTPS plan to include internal-certificate application path while certificate issuance is pending.
- Confirmed Ubuntu target server/DNS: `lascrtmp01.ahs.int` and DNS resolution is already in place.
- Confirmed Ubuntu server IP address: `10.241.18.15`.
- Confirmed deployment scope is internal-only (no internet exposure).
- Added documented rollback procedure to return from HTTPS to HTTP if TLS cutover fails.
- Updated Offboard User web mapping to Option 10 and aligned backend logic to remove CSF/BOT/TCT devices, delete Unity mailbox, and mark all associated DNs inactive.
- Renamed Option 10 web text to "Offboard User - Delete all Jabber and Voicemail Box (Option 10)".
- Added new web options 3/4/5 for secondary device workflows: TCT, BOT, and STRIKE MODE (TCT+BOT), including FastAPI routes and toolkit backend logic.

## Working Agreement
- Update this file at the end of each substantial change set.
- Keep entries brief and action-oriented.
- Move items from Pending to In Progress to Completed as work advances.

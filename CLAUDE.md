# Cisco CUCM Project Tracker

This file is the single source of truth for ongoing goals, pending tasks, and key decisions across our conversations.

## Last Updated
- Date: 2026-05-01
- Updated by: GitHub Copilot

## Active Goals
- Establish and maintain a centralized, continuously updated project tracker in this file.
- Maintain current working FastAPI web portal that executes imported CUCM automation scripts.
- Migrate external access from HTTP to HTTPS on Ubuntu Server 24.04.
- Keep service internal-only with no internet exposure.

## Pending Tasks
- [ ] Complete HTTPS cutover with Nginx reverse proxy using internally signed certificate.
- [ ] Apply internal certificate files (cert/key/chain), validate Nginx TLS config, and enforce HTTP -> HTTPS redirect.
- [ ] Define internal certificate renewal/rotation procedure and owner.
- [ ] Confirm internal subnet allow-list for UFW/Nginx access control.
- [ ] Document deployment/runtime prerequisites (Python env, FastAPI/Uvicorn, network access to CUCM/Unity).
- [ ] Centralize environment-specific values (CUCM hosts, Unity hosts, partitions, default PIN) into config/env vars.
- [ ] Add lightweight health check and structured error responses for web routes.
- [ ] Add minimal regression tests for toolkit functions that generate CSV outputs.

## Enhancement Backlog
- [ ] [P1][Planned] Convert HTTP to HTTPS using internally signed enterprise certificate, with Nginx TLS termination and HTTP -> HTTPS redirect.
- [ ] [P1][Idea] Add input validation and user-friendly error display on all web forms.
- [ ] [P1][Idea] Add reusable environment/config file for CUCM/Unity hosts, partitions, and defaults.
- [ ] [P1][In Progress] Remediate Ubuntu 24.04 vulnerabilities and clean up host hardening findings (SNOW TASK0723797).
  - [x] CVE-2024-6387 (CVSSv3 8.1) — OpenSSH patched to 9.6p1-3ubuntu13.16 ✓
  - [ ] FTP unencrypted (CVSSv3 7.5) — vsftpd stopped; blocked on Sean Beavers identifying 10.241.17.165 before disabling
  - [ ] SSH Weak MACs (CVSSv3 7.5) — 1 of 4 removed; 3 remaining (umac-64@openssh.com, hmac-sha1-etm@openssh.com, hmac-sha1); Cisco CER backup test passed
  - [ ] CVE-2025-61984 (CVSSv3 3.6) — Not started
- [ ] [P1][Idea] Before creating Jabber devices or voicemail, always verify whether the target resource already exists to prevent duplicate provisioning and resource waste.
- [x] [P2][Done] After job submission, clear the "User ID for person..." input field to prevent accidental repeat Jabber creation.
- [ ] [P2][Idea] Refresh the web portal theme to align with AMN Healthcare visual style (brand colors, typography, spacing, and overall look/feel).
- [ ] [P2][Idea] Add per-option success/failure summary panel in the UI after CSV generation.
- [ ] [P2][Idea] Add a lightweight audit trail (who ran what option and when) for internal operations.
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
- Waiting on internal PKI signed certificate issuance before final HTTPS activation.
- HTTPS migration target host confirmed: `lascrtmp01.ahs.int` (DNS already working).
- Ubuntu server IP confirmed: `10.241.18.15`.

## Completed Tasks
- [x] Created central project tracking structure in `CLAUDE.md`.
- [x] Confirmed current scripts and pages are working as baseline behavior.

## Key Decisions
- 2026-04-30: Use `CLAUDE.md` as the canonical running log for goals, pending tasks, and key decisions for this repository.
- 2026-04-30: Treat current `main.py` routes and `toolkit/` scripts as the stable working baseline.
- 2026-04-30: Prioritize reliability and maintainability improvements next, while preserving existing workflow behavior.
- 2026-04-30: Standardize production exposure as HTTPS via Nginx, with Uvicorn bound to localhost only.
- 2026-04-30: Use internally signed enterprise certificate for Ubuntu production TLS cutover.
- 2026-04-30: Environment remains internal-network only; no internet exposure planned.

## Open Questions
- Which immediate deliverable should be prioritized first in this repository?
- `10.241.17.165`: Unknown FTP client connecting to vsftpd — asked Sean Beavers to identify; suspected networking device sending backups. Pending confirmation on whether it can switch to SFTP.

## Conversation Notes
- Keep this section concise with short chronological notes after significant updates.

### 2026-05-01
- TASK0723797: vsftpd log analysis showed two FTP clients: `10.241.18.11` (CUCM CDR uploads, confirmed) and `10.241.17.165` (unknown — suspected networking device sending backups).
- Reached out to Sean Beavers to identify `10.241.17.165` and assess whether it can migrate to SFTP.
- vsftpd remains stopped; CDR uploads from CUCM are not flowing until decision is made.
- SSH MAC hardening in progress: 1 of 4 weak MACs removed; 3 remaining (umac-64@openssh.com, hmac-sha1-etm@openssh.com, hmac-sha1); removing one at a time on user schedule.
- Validation: Cisco CER backup works after Weak MAC hardening change (pass).
- Production CUCM confirmed: `lascucmpp01.ahs.int` (10.241.18.11), System version: 15.0.1.12900-234.
- Production Unity Connection confirmed: `lascutyp01.ahs.int` (10.241.18.17), System version: 15.0.1.12900-43.
- LAB CUCM confirmed: `lascucmpl01.ahs.int` (10.241.18.200), System version: 15.0.1.14901-2.
- LAB Unity Connection confirmed: `lascutypl01.ahs.int` (10.241.18.202), System version: 15.0.1.13900-61.
- Terminology: CallManager = Cisco Unified Communications Manager (CUCM).
- UI enhancement implemented: target "User ID for person..." field now clears immediately after form submission on target-user workflows.

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
- Renamed Option 10 web text to "Offboard User - Delete all Jabber (Option 10)".
- Added new web options 3/4/5 for secondary device workflows: TCT, BOT, and STRIKE MODE (TCT+BOT), including FastAPI routes and toolkit backend logic.

## Working Agreement
- Update this file at the end of each substantial change set.
- Keep entries brief and action-oriented.
- Move items from Pending to In Progress to Completed as work advances.

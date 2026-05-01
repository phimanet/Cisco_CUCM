# Cisco CUCM Project Tracker

This file is the single source of truth for ongoing goals, pending tasks, and key decisions across our conversations.

## Last Updated
- Date: 2026-04-30
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

## Conversation Notes
- Keep this section concise with short chronological notes after significant updates.

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

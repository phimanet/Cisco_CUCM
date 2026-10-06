---
description: "Use when creating, changing, or reviewing queues, background workers, jobs, saved reports, audit history, retention, or restart recovery."
applyTo: "**/*.py"
---

# Queue and History Persistence

- Apply this standard to every queue/history workflow, not only new features. Do not claim an existing queue is compliant without inspecting its storage, startup recovery, and focused tests; record noncompliant legacy paths for controlled LAB-first remediation.
- Persist active jobs, progress/cursors, per-item outcomes, errors, and retained history in the configured runtime data root, outside tracked Git files. On Ubuntu the default existing data root is `/opt/cucm-web-data`; honor configured overrides. Browser refresh/closure, service/server restart, and normal source-code pulls/checkouts must not erase this data.
- Restore queued/running work safely at startup; retain paused/cancelled state and do not silently restart cancelled work. Where execution needs renewed operator credentials, restore the job and visibly block until authorized credentials are available rather than discard it.
- Checkpoint completed items. Do not blindly replay completed mutations; reconcile an in-flight mutation with the external system after a crash before retrying. Read-only work may be repeated where necessary, but document that behavior and preserve available results.
- Save state atomically with fsync, refuse to overwrite corrupt/unreadable state, and keep the last successful report when a refresh fails. Persist the completed report before marking the job completed. Catch per-job worker exceptions so later queued jobs remain executable.
- Preserve account/host/environment boundaries and job identity checks. Re-read current configuration/credentials for resumed work; never persist plaintext passwords, auth tokens, or raw sensitive provider payloads. Use only approved encrypted credential storage when a workflow requires it.
- Make retention explicit: distinguish latest-job/latest-report-only storage from an archive of past jobs. Retain history according to its documented count/time policy; never silently describe a latest-only snapshot as full job history. Active work must not be pruned by ordinary history retention.
- Provide authenticated saved-state/history access after restart. Do not depend on browser memory, local storage, or a tab staying open as the only durable record. A background queue must continue independently of the browser; a browser-driven scan must clearly expose saved progress and Resume.
- Verify persist/reload, startup resume, no duplicate completed mutations, failure retention, corrupt/write-failed storage, declared retention boundaries, and worker exception survival with focused checks. Disclose any unverified existing workflows.
- Normal restarts/code resets are not equivalent to deleting the runtime data directory or restoring an older VM/data snapshot. Document those recovery limits and backup requirements; Git alone does not back up external queue/history data.
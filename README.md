# DE&TH Detection-Engineering

This repository contains detection engineering work and lab artifacts, organized by detection language and platform.

## Structure
- `sigma/` — Sigma rules (planned)
- `yara/` — YARA rules and write-ups (static analysis only; no detonation)
- `kql/` — Microsoft Sentinel KQL (planned)
- `splunk/` — Splunk SPL (planned)
- `*/docs/` — Write-ups live beside their detection type (e.g., `yara/docs/`, `sigma/docs/`)


## Notes
- Malware samples are analyzed using **static techniques** unless explicitly stated otherwise.
- Rules are written to favor **high-signal, behavior-based indicators** where possible.

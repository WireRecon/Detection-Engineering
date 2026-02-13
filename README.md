# DE&TH Detection-Engineering

This repository contains detection engineering work and lab artifacts, organized by detection language and platform.

## Structure
- `sigma/` — Sigma rules (planned)
- `yara/` — YARA rules and write-ups (static analysis only; no detonation)
- `kql/` — Microsoft Sentinel KQL (planned)
- `splunk/` — Splunk SPL (planned)
> Note: Write-ups (.md) live inside each detection folder (e.g., `yara/docs/`, `sigma/docs/`) to keep documentation scoped to that detection type.

## Notes
- Malware samples are analyzed using **static techniques** unless explicitly stated otherwise.
- Rules are written to favor **high-signal, behavior-based indicators** where possible.

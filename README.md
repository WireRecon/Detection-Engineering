# DE&TH Detection-Engineering

This repository contains detection engineering work and lab artifacts, organized by detection language and platform.

<!--<div align="center"> -->
<img src="Detection-Engineering/analysis/images/banner_2.png" alt="Cover Picture" width="75%"><br>
<!-- </div> -->

## Structure
- `yara/` — YARA rules and write-ups (static analysis only; no detonation)
- `sigma/` — Sigma rules (planned)
- `kql/` — Microsoft Sentinel KQL (planned)
- `splunk/` — Splunk SPL (planned)

## Notes
- Write-ups (.md) live inside each detection folder (e.g., `yara/docs/`, `sigma/docs/`) to keep documentation scoped to that detection type.
- Malware samples are analyzed using **static techniques** unless explicitly stated otherwise.
- Rules are written to favor **high-signal, behavior-based indicators** where possible.
 where possible.

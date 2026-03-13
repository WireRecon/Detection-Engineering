
<div align="center"> 
<img src="/assets/images/banner_2.png" alt="Cover Picture" width="75%">
</div> 

# Detection-Engineering

This repository contains detection engineering work and lab artifacts, organized by detection language and platform.

## Structure
- `sigma/` — Sigma rules (planned)
- `yara/` — YARA rules and static malware analysis write-ups
- `snort/` — Snort intrusion detection rules
- `kql/` — Microsoft Sentinel KQL (planned)
- `splunk/` — Splunk SPL (planned)

## Notes
- Write-ups (.md) live inside each detection folder (e.g., `yara/docs/`, `sigma/docs/`) to keep documentation scoped to that detection type.
- Malware samples are analyzed using **static techniques** unless explicitly stated otherwise.
- Rules are written to favor **high-signal, behavior-based indicators** where possible.


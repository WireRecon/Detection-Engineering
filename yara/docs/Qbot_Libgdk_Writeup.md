# Qbot DLL Sample – YARA Rule Notes

## What this detects
A fingerprint-style YARA rule for a Qbot-related DLL sample using a unique string cluster from the library:
`libgdk-win32-2.24.28_i386`.

## How it’s used maliciously
Qbot (QakBot) is commonly used for:
- Credential theft
- Persistence and lateral movement tooling
- Downloading additional payloads

This rule is intended to catch this specific sample/library string set, not all Qbot variants.
---
## Files
- Rules: `win_libgdk_win32_2.24.28_i386_sample_fingerprint.yar`
---

## Analysis scope
Static only (no detonation).

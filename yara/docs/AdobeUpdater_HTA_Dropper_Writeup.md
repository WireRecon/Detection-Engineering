# AdobeUpdater HTA Dropper (Lab) — YARA Detection Write-up

## Overview
This write-up documents a lab-built HTA dropper themed as an “Adobe Acrobat Updater.” The objective is defensive: demonstrate static analysis and a resilient YARA rule for detecting the dropper artifact.

## Sample
- File: `AdobeUpdater.hta`
- SHA256: `05abb37f26f3066e26bbe46f813128d7935a0c6fb8cb5cb8c35f7fa15acf9eac`
- Analysis: Static only

## Observed Behaviors (Static Indicators)
High-signal indicators present in the HTA:
- HTA application markers (e.g., `<HTA:APPLICATION`)
- WSH usage via `WScript.Shell`
- Hidden PowerShell execution pattern
- Run-key persistence:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Reverse-shell style networking via `System.Net.Sockets.TCPClient`

## Detection
### Rule
- `MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.yar`

### Detection Logic
The rule requires a cluster of high-signal artifacts:
- HTA markers + Adobe-themed lure string
- `WScript.Shell` usage
- Hidden PowerShell execution pattern
- Run-key persistence indicator
- TCPClient networking indicator

## Testing
### Positive test
```bash
yara -s -w MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.yar AdobeUpdater.hta

```
## False-positive sanity check (benign-ish)
```bash
yara -r -w MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.yar /usr/share/doc 2>/dev/null | head
```

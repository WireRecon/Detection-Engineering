# YARA Rules

This folder contains YARA rules developed from static malware analysis and lab exercises.

## Table of Contents
- AsyncRAT (.NET)
- Qbot sample
- DarkGate loader + payload DLLs
- Bitdefender Trufos component
---

## AsyncRAT (.NET)
- **MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer.yar**  
  Behavior-based detection for AsyncRAT-like samples using plugin, wallet, token, and hosts/proxy artifacts.

- **IOC_AsyncRAT_winscapmarzo_duckdns_9003.yar**  
  Narrow IOC rule for this specific lab sample’s C2.

See: `docs/AsyncRAT_Writeup.md` for analysis notes.

## Qbot sample
- **win_libgdk_win32_2.24.28_i386_sample_fingerprint.yar**  
  Fingerprint-style rule based on unique strings from a Qbot-related DLL sample.

See: `docs/Qbot_Libgdk_Writeup.md` for analysis notes.

## DarkGate loader + payload DLLs
- **MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.yar**  
  Detects a Windows x64 loader/dropper that stages embedded resources into `WindowsApps` and launches a staged DLL via `rundll32`, with CDN/module path artifacts.

- **MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade.yar**  
  Detects DarkGate-related x64 payload DLLs masquerading as Windows system libraries (`cryptbase.dll` / `wldp.dll`) via characteristic export-name sets.

See: `docs/DarkGate_Writeup.md` for analysis notes.

## Bitdefender Trufos component (lab-labeled: latrodectus.exe)
- **GEN_WIN_Bitdefender_Trufos_DLL.yar**  
  Identifies Bitdefender Trufos user-mode component (TRUFOS.DLL) using a resilient cluster of dev/build artifacts and a distinctive RB* export surface (static-only classification).

See: `dSee: `docs/GEN_WIN_Bitdefender_Trufos_DLL.md` for analysis notes.





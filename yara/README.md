# YARA Rules

This folder contains YARA rules developed from static malware analysis and lab exercises.

## AsyncRAT (.NET)
- **MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer.yar**  
  Behavior-based detection for AsyncRAT-like samples using plugin, wallet, token, and hosts/proxy artifacts.

- **IOC_AsyncRAT_winscapmarzo_duckdns_9003.yar**  
  Narrow IOC rule for this specific lab sample’s C2.

See: `docs/AsyncRAT_Writeup.md` for analysis notes.

## Qbot sample
- **win_libgdk_win32_2.24.28_i386_sample_fingerprint.yar**  
  Fingerprint-style rule based on unique strings from a Qbot-related DLL sample.


# MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer — Detection Rule (YARA)

## Artifacts
- Rule: `yara/MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer.yar`
- Companion IOC rule: `yara/IOC_AsyncRAT_winscapmarzo_duckdns_9003.yar`

## Summary
Behavior-focused YARA rule targeting a .NET AsyncRAT-like sample with the following observed capabilities:

- Plugin/module framework with MsgPack-based C2 messaging
- Discord token theft (`DicordTokens` — notable misspelling preserved from source)
- Crypto wallet and browser credential harvesting (Chrome, Firefox, MetaMask, Exodus, Electrum)
- Hosts file and proxy manipulation (`KillProxy`, `ResetHosts`, `hosts.backup`)
- Windows Defender exclusion and AV removal
- Persistence via scheduled task and reversed Run key string

This rule is designed to be **variant-resilient** — it targets capability markers and behavioral patterns rather than hard IOCs, so it can survive minor repacking or reconfiguration. For tight sample-specific matching, use the companion IOC rule.

---

## Sample Details (Observed)
- **File:** `asyncrat.exe`
- **Type:** Windows PE32 (x86) .NET assembly (GUI)
- **Analysis scope:** Static only — sample was not executed

### Hashes
- **SHA256:** `8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb`

### Decrypted C2 (from AES-encrypted config blobs in Settings.cs)
- **Host:** `winscapmarzo.duckdns.org`
- **Port:** `9003`

---

## Observed Behaviors

### 1. Plugin Framework + MsgPack Messaging
The sample uses a plugin-based architecture allowing the operator to push modules to the victim and exchange structured messages:

- `Plugin.Plugin`, `sendPlugin`, `savePlugin`, `Plugins`
- `Msgpack` / MsgPack-related strings

### 2. Credential, Token, and Crypto Wallet Targeting
Multiple indicators confirm theft of browser credentials, Discord tokens, and crypto wallet artifacts:

- `DicordTokens` (Discord token theft — misspelling preserved from source binary)
- `WebBrowserPass`, `Password`, `Tokens`
- Chrome/Brave/Edge Local Extension Settings paths
- MetaMask extension ID: `nkbihfbeogaeaoehlefnkodbefgpgknn`
- Wallet markers: Exodus, Electrum, Ledger Live, ErgoWallet

### 3. Defense Evasion + System Tampering
- `WDExclusion` — Windows Defender exclusion
- `AVRemoval.Class1` — AV removal module
- `KillProxy`, `BackProxy.Class1` — proxy manipulation
- Hosts file tampering: `\drivers\etc`, `\hosts.backup`, `ResetHosts`, `127.0.0.1 Blocked!`
- Browser disruption: `cmd.exe /c taskkill.exe /im chrome.exe /f`

### 4. Persistence
Observed in `NormalStartup.Install()`:
- Scheduled task via `schtasks /create /f /sc onlogon /rl highest`
- Reversed Run key string (obfuscated registry path)
- Batch-based delay: `@echo off` / `timeout 3 > NUL`

---

## Detection Logic

### Gate
```
uint16(0) == 0x5A4D                             // MZ header
pe.imports("mscoree.dll", "_CorExeMain")        // .NET assembly
```

### Condition
```
6 of ($cap*)    // 6+ capability markers (plugin framework, evasion, tampering)
1 of ($path*)   // at least one wallet/browser/hosts path indicator
2 of ($per*)    // at least 2 persistence indicators
```

---

## False Positives / Limitations

**False positives:** Unlikely. The required combination of plugin framework artifacts, hosts/proxy tampering strings, and wallet harvesting paths is not present in legitimate .NET software.

**Limitations:** This rule targets behavioral patterns from this specific observed sample. If a future variant renames modules, changes class names, or drops the plugin framework entirely, coverage may degrade. In that case, the condition threshold can be lowered or new string sets added.

---

## How to Use
```bash
yara -s yara/MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer.yar <path_to_suspect_file_or_directory>
```

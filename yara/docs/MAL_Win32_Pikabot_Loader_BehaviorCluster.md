# MAL_Win32_Pikabot_Loader_BehaviorCluster — Detection Rule (YARA)

## Artifacts
- Rule: `yara/MAL_Win32_Pikabot_Loader_BehaviorCluster.yar`
- Companion marker rule: `yara/MAL_Win32_Pikabot_Loader_UniqueMarkers.yar`

## Summary
Behavior-focused detection rule for a Pikabot loader masquerading as Qihoo 360 File Smasher (`QHFileSmasher.exe`). Rather than relying on the unique crypto marker, this rule targets the combination of the version resource masquerade identity, anti-360 AV driver blocking configuration, and confirmed WININET network capability — making it more resilient to payload re-encoding or marker rotation between builds.

---

## Sample Details (Observed)
- **Submitted filename:** `pikabot.exe`
- **Masquerade identity:** `QHFileSmasher.exe` — Qihoo 360 File Smasher Application v9.6.0.1034
- **Type:** Windows PE32 (x86) executable
- **Analysis scope:** Static only — sample was not executed

### Hashes
- **SHA256:** `7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e`

---

## Observed Behaviors

### 1. Qihoo 360 File Smasher Masquerade
The PE version resource is populated with Qihoo 360 branding to appear as a legitimate security tool:

| Field | Value |
|-------|-------|
| CompanyName | Qihoo 360 Technology Co. Ltd. |
| FileDescription | File Smasher Application |
| InternalName | QHFileSmasher |
| OriginalFilename | QHFileSmasher.exe |
| FileVersion | 9, 6, 0, 1034 |

### 2. Anti-360 AV Driver Blocking
The loader contains configuration strings stored as UTF-16LE in the `.rsrc` XML config, specifically targeting and blocking Qihoo 360 security components — the same vendor it masquerades as:

- `block_driver_root=true`
- `block_ts_install_path=true`
- `360FsFlt.sys` — 360 filesystem filter driver
- `360SelfProtection.sys` — 360 self-protection driver
- `360AvFlt` — 360 AV filter

### 3. System Manipulation
- `Software\360Safe\Liveup` — 360 Safe update registry key targeting
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards` — network adapter enumeration
- `sc.exe` — confirmed via FLOSS decoded strings (runtime-decoded, not present as a static string; excluded from rule condition)

### 4. Runtime-Decoded Strings (FLOSS)
Several strings are obfuscated in the binary and only resolved at runtime:
- `sc.exe` — service control binary
- `\360TotalSecurity` — 360 install path targeting
- `!cILryP$LsPSiLpN` — the crypto marker also appears as a decoded string, confirming active runtime use
- Partial marker fragments (`sPSi`, `PSiLpN`, `PSiLp`, `PSiL`) — encoding boundary fragments decoded at runtime

### 5. Network Capability (WININET)
Confirmed WININET imports from `rabin2` import analysis:
- `InternetOpenW`, `InternetOpenUrlW`
- `InternetReadFile`, `HttpQueryInfoW`
- `InternetSetOptionW`, `DeleteUrlCacheEntryW`
- `InternetCloseHandle`

Hardcoded user-agent observed:
- `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)`

Disassembly at `0x00454fde` confirms active WININET usage in the execution flow (`HttpQueryInfoW`, `InternetReadFile`, `InternetCloseHandle` called in sequence).

### 6. Additional Import Capabilities
From the full import table (`rabin2 -i`), the loader also imports:
- `RPCRT4.dll` — RPC async client calls (`NdrAsyncClientCall`, `RpcAsyncInitializeHandle`)
- `PSAPI.DLL` — process enumeration (`GetModuleFileNameExW`)
- `WTSAPI32.dll` — session query (`WTSQuerySessionInformationW`)
- `gdiplus.dll` — GDI+ rendering (consistent with fake UI from masquerade)

---

## Detection Logic

### Gate
```
pe.is_pe                         // valid PE
filesize < 3MB                   // loader size constraint
pe.number_of_signatures == 0     // unsigned binary
```

### Condition
```
2 of ($ver_*)     // 2+ version resource masquerade strings (UTF-16LE)
3 of ($av_*)      // 3+ anti-360 driver/config strings (UTF-16LE in .rsrc XML config)
pe.imports("WININET.dll", "InternetOpenW" or "InternetOpenUrlW")  // active WININET
```

Note: `sc.exe`, `\360TotalSecurity`, and registry path strings are confirmed runtime-decoded via FLOSS and are therefore not usable as static detection anchors. The three-clause combination above is sufficient — the masquerade identity paired with anti-360 evasion artifacts and WININET imports is highly specific to this loader.

---

## False Positives / Limitations

**False positives:** Low. Legitimate Qihoo 360 software will not contain configurations to block its own drivers. The combination of the masquerade identity and anti-360 artifacts is self-contradictory in any legitimate binary.

**Limitations:** This rule depends on the masquerade identity remaining consistent. A future Pikabot build using a different lure binary would evade this rule. In that case, the companion marker rule may still fire if the encoding scheme is unchanged.

---

## How to Use
```bash
yara -s yara/MAL_Win32_Pikabot_Loader_BehaviorCluster.yar <path_to_suspect_file_or_directory>
```

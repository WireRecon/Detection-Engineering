# MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade — Detection Rule (YARA)

## Artifacts
- Rule: `yara/MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade.yar`
- Companion loader rule: `yara/MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.yar`

## Summary
Detects DarkGate payload DLLs that masquerade as legitimate Windows system libraries by presenting export name sets characteristic of `cryptbase.dll` and/or `wldp.dll`. These DLLs are embedded in the DarkGate loader, extracted at runtime, and dropped into the `WindowsApps` directory where they are side-loaded to execute the DarkGate payload.

---

## Sample Details (Observed)
- **Parent loader:** `darkgate.exe`
- **Type:** Windows PE32+ (x64) DLL
- **Masquerade targets:** `cryptbase.dll`, `wldp.dll`
- **Drop location:** `%LOCALAPPDATA%\Microsoft\WindowsApps\`
- **Analysis scope:** Static only — sample was not executed

### Hashes
- **Parent loader SHA256:** `056286b15e58ccc9f77873ef22c42e3b098860940990dbb7543e7f469ce7a2f6`

---

## Observed Behaviors

### 1. cryptbase.dll Masquerade
The payload DLL exports a set of `SystemFunction00x` names that mirror the real `cryptbase.dll` export table, enabling DLL side-loading via applications that import from `cryptbase`:

- `SystemFunction001` through `SystemFunction005`
- `SystemFunction028`, `SystemFunction029`
- `SystemFunction034`, `SystemFunction036`
- `SystemFunction040`, `SystemFunction041`

### 2. wldp.dll Masquerade
The payload also presents WLDP (Windows Lockdown Policy) export names, allowing side-loading via applications that call into WLDP for code integrity policy checks:

- `WldpQueryWindowsLockdownMode`
- `WldpQuerySecurityPolicy`
- `WldpSetDynamicCodeTrust` / `WldpSetDynamicCodeTrust2`
- `WldpIsDynamicCodePolicyEnabled`
- `WldpIsAppApprovedByPolicy`
- `WldpAddDeveloperCertificateForDynamicCodeTrust`

### 3. Infection Chain Context
These DLLs are not standalone — they are delivered by the DarkGate loader and staged to `WindowsApps` before side-loading. Detection of these DLLs outside of `C:\Windows\System32\` or `C:\Windows\SysWOW64\` is a strong indicator of compromise.

---

## Detection Logic

### Gate
```
uint16(0) == 0x5A4D              // MZ header
pe.machine == MACHINE_AMD64      // x64
(pe.characteristics & 0x2000)    // DLL flag set
```

### Condition
The rule fires on any of three scenarios:
```
(7 of ($cb*) and 4 of ($w*))     // Both cryptbase AND wldp export sets present
(7 of ($cb*) and not 1 of ($w*)) // cryptbase-only masquerade
(4 of ($w*) and not 1 of ($cb*)) // wldp-only masquerade
```

This structure allows detection of both combined and split payload variants.

---

## False Positives / Limitations

**False positives:** Low. Legitimate `cryptbase.dll` and `wldp.dll` will not appear together in the same binary, will not be found outside their expected system paths, and will be signed by Microsoft. Any unsigned match outside `System32` or `SysWOW64` warrants immediate investigation.

**Limitations:** This rule detects the masquerade export pattern. If a future DarkGate variant uses a different system DLL as a masquerade target, new export string sets would need to be added. Consider pairing with path-based detections (EDR/SIEM alerts for unsigned DLLs written to `WindowsApps`) for full coverage.

---

## How to Use
```bash
yara -s yara/MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade.yar <path_to_suspect_file_or_directory>
```

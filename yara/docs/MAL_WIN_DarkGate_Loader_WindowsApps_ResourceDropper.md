# MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper — Detection Rule (YARA)

## Artifacts
- Rule: `yara/MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.yar`
- Companion payload rule: `yara/MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade.yar`

## Summary
Detects the DarkGate loader/dropper stage — a Windows x64 GUI binary that masquerades as a Microsoft ApiSet Stub DLL (`apisetstub`), extracts embedded resource payloads, stages them into the `WindowsApps` directory, and executes them via `rundll32`. The loader communicates with a CDN-based staging infrastructure and includes active anti-VM checks against VMware and VirtualBox environments.

---

## Sample Details (Observed)
- **File:** `darkgate.exe`
- **Type:** Windows PE32+ (x64) GUI binary
- **Masquerade identity:** `apisetstub` — claims to be Microsoft ApiSet Stub DLL v10.0.17763.1
- **Analysis scope:** Static only — sample was not executed

### Hashes
- **SHA256:** `056286b15e58ccc9f77873ef22c42e3b098860940990dbb7543e7f469ce7a2f6`

---

## Observed Behaviors

### 1. Masquerade Identity
The PE version resource claims:
- **CompanyName:** Microsoft Corporation
- **FileDescription:** ApiSet Stub DLL
- **OriginalFilename:** apisetstub
- **ProductVersion:** 10.0.17763.1

This is a deliberate attempt to appear as a legitimate Windows system component.

### 2. Resource Extraction + WindowsApps Staging
The loader extracts embedded resources and drops them into the `WindowsApps` directory — a location that is often excluded from AV scanning:

- `\...\Local\Microsoft\WindowsApps\cleanhelper.dll`
- `\...\Local\Microsoft\WindowsApps\runsysclean.dll`
- `\...\Local\Microsoft\WindowsApps\cryptbase.dll`
- `\...\Local\Microsoft\WindowsApps\wldp.dll`

Resource extraction is performed via explicit function calls:
- `extract_resource_to_file(CLEANHELPER, full_path)`
- `extract_resource_to_file(RUNSYSCLEAN, full_path)`

### 3. Execution Chain
After dropping the DLLs, the loader executes via a `cleanmgr.exe` + `rundll32` chain:

- `C:\windows\system32\cleanmgr.exe`
- `rundll32 cleanhelper.dll T34 /k funtic321 1`

### 4. CDN-Based Staging Infrastructure
Module paths observed pointing to an actor-controlled CDN:

- `cdn3-adb1.online`
- `abdwufkw/modules/cleanhelper.png`
- `abdwufkw/modules/runsysclean.png`
- `abdwufkw/modules/legacy_l1.png`

Payloads are disguised as `.png` files to avoid network-level detection.

### 5. Anti-VM / Anti-Analysis
FLOSS stack string analysis revealed active virtual machine detection:

- `dll_check() [ERROR]: Virtual Machine Detected: VMW` (VMware)
- `dll_check() [ERROR]: Virtual Machine Detected: Vir` (VirtualBox)

### 6. C2 Communication
Hardcoded user-agent observed in static strings:
- `WinHTTP Example/1.0`

---

## Detection Logic

### Gate
```
uint16(0) == 0x5A4D          // MZ header
pe.machine == MACHINE_AMD64  // x64
pe.subsystem == WINDOWS_GUI  // GUI binary
not pe.is_signed             // unsigned
```

### Condition
```
3 of ($drop*)                         // 3+ WindowsApps drop path indicators
1 of ($exec*)                         // at least one execution chain string
( $stage1 or 1 of ($mod*) )          // CDN domain or module path present
```

---

## False Positives / Limitations

**False positives:** Unlikely. The required combination of WindowsApps drop paths, resource extraction function calls, and CDN module paths is not present in legitimate software.

**Limitations:** If the actor changes the CDN domain, drop paths, or execution command, the rule may need updating. The anti-VM and user-agent strings (`$avm*`, `$ua1`) are declared in the rule but not required in the condition — they serve as supporting context for analysts and can be promoted to required indicators in higher-confidence environments.

---

## How to Use
```bash
yara -s yara/MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.yar <path_to_suspect_file_or_directory>
```

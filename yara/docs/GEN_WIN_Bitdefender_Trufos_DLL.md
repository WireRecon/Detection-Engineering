# GEN_WIN_Bitdefender_Trufos_DLL — Detection Rule (YARA)

## Artifacts
- Rule: `yara/GEN_WIN_Bitdefender_Trufos_DLL.yar`

## Summary
This rule identifies the Bitdefender Trufos user-mode component (`TRUFOS.DLL`) via dev/build artifacts, a distinctive `RB*` export name cluster, and Trufos-specific IPC and runtime markers. The observed sample was delivered renamed as `latrodectus.exe` — a classic masquerade technique where a threat actor bundles or stages a legitimate security DLL under a misleading filename.

Static analysis reveals no behavioral indicators of malicious code within the binary itself. The detection value is in **context**: this file appearing outside a legitimate Bitdefender installation path, renamed, or loaded by an unexpected process is a strong indicator of staged abuse or DLL side-loading.

---

## Sample Details (Observed)
- **Submitted filename:** `latrodectus.exe`
- **True identity:** `TRUFOS.DLL` — Bitdefender Trufos API component
- **Type:** Windows PE32+ (x64) DLL
- **Analysis scope:** Static only — sample was not executed

### Hashes
- **SHA256:** `aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c`
- **MD5:** `da8ae8e1de522b20a462239c6893613e`
- **Imphash:** `dad9f669bb19a6ea9c2b335d7292cfc7`
- **PE TimeDateStamp:** `2022-04-13` (0x62576057)

### Version Resource (embedded)
| Field | Value |
|-------|-------|
| CompanyName | Bitdefender |
| FileDescription | Trufos API |
| FileVersion | 2.5.4.62.761d05c Free Build |
| InternalName | TRUFOS.DLL |
| OriginalFilename | TRUFOS.DLL |
| ProductName | Bitdefender Antivirus |

---

## Observed Indicators

### 1. Dev / Build Artifacts
Source path and PDB references confirm this is a genuine Bitdefender build artifact:
- Build path fragments: `...\ARK23181_2\trufos_dll\*.c`
- PDB reference: `...\Release\trufos.pdb`

### 2. RB* Export Surface
A distinctive cluster of math/image-processing style exports consistent with a Trufos processing library:
- `RBCalcAvgW`, `RBCalcMaxW`, `RBCalcMin`, `RBCalcSum`, `RBCalcDev`
- `RBGrayscale`, `RBInvertColor`, `RBMonochrome`

### 3. Trufos-Specific IPC and Runtime Markers (confirmed via FLOSS)
Runtime artifacts unique to the Trufos component:
- `TRFCOMMPORT` — named communication port
- `Global\Trf01` — global mutex/event
- `\Systemroot\TrfDefData.tmp` — Trufos temp data file
- `TrfArc` — Trufos archive component reference

### 4. Minifilter Communication Imports (from FLTLIB.DLL)
- `FilterConnectCommunicationPort`
- `FilterSendMessage`, `FilterGetMessage`, `FilterReplyMessage`
- `FilterLoad`

These are consistent with a user-mode component communicating with a kernel minifilter driver — expected behavior for a security product.

### 5. Additional Capability Indicators
- `SeLoadDriverPrivilege`, `SeBackupPrivilege` — elevated privilege usage
- `\\.\\PhysicalDrive%d` — raw disk access
- `\system32\config\`, `\Registry\Machine\` — registry and system config access
- `cmdFileDelete`, `cmdFileCopy`, `cmdRegModifyValue`, `cmdRegDeleteValue` — internal command handler strings
- `\\pipe\\`, `\\BaseNamedObjects\\` — IPC channel markers

---

## Detection Logic

### Gate
```
uint16(0) == 0x5A4D              // MZ header
pe.is_pe                         // valid PE
pe.machine == MACHINE_AMD64      // x64
(pe.characteristics & pe.DLL)   // DLL flag set
```

### Condition (three paths)
```
Primary:   2 of ($dev_*) and 5 of ($exp*)                          // dev artifacts + RB* exports
Secondary: 2 of ($vnd_*) and 5 of ($exp*) and 2 of ($trf*)        // vendor metadata + RB* + Trufos IPC
Fallback:  2 of ($vnd_*) and 5 of ($exp*) and 2 of ($flt*)        // vendor metadata + RB* + FLTLIB imports
```

---

## False Positives / Limitations

**False positives:** Low. Legitimate `TRUFOS.DLL` in its expected Bitdefender installation directory is benign. The rule is intentionally designed to fire on the file regardless of path — investigation should focus on **where** the file is and **what loaded it**, not whether it matches.

**Limitations:** This is a component identification rule, not a malware detection rule. Its value is entirely contextual — the file itself is not malicious, but its presence in unexpected locations or loaded by unexpected processes is a strong investigative lead.

---

## How to Use
```bash
yara -s yara/GEN_WIN_Bitdefender_Trufos_DLL.yar <path_to_suspect_file_or_directory>
```

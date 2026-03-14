# MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike — Detection Rule (YARA)

## Artifacts
- Rule: `yara/MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike.yar`

## Summary
Detects a Delphi/Inno Setup installer stub masquerading as **Freemake Video Converter** that carries an embedded payload in a large overlay region beyond the final mapped PE section. The binary presents a deliberately constructed legitimacy stack — Freemake version resource identity, embedded Piriform Software Ltd (CCleaner) and Avast certificate chains in the overlay — but Authenticode signature verification fails, exposing the forgery. The Inno Setup LZMA decompressor and setup-data markers confirm this is a dropper wrapper, not a legitimate installer.

---

## Sample Details (Observed)
- **Submitted filename:** `IcedID.exe`
- **Masquerade identity:** Freemake Video Converter v4.1.10.109
- **Compiler/Language:** Delphi (Object Pascal) — confirmed via FastMM allocator strings and Delphi RTL markers
- **Installer framework:** Inno Setup 5.5.x with LZMA compression
- **Type:** Windows PE32 (x86) GUI executable
- **Analysis scope:** Static only — sample was not executed

### Hashes
- **SHA256:** `cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc`

### Version Resource (claimed identity)
| Field | Value |
|-------|-------|
| CompanyName | Freemake |
| FileDescription | Freemake Video Converter |
| ProductName | Freemake Video Converter |
| FileVersion | 4.1.10.109 |
| Comments | This installation was built with Inno Setup. |

---

## Observed Indicators

### 1. Inno Setup Installer Framework
Confirmed Inno Setup 5.5.x internals via FLOSS static string analysis:

- `Inno Setup Setup Data (5.5.7) (u)` — setup data block marker
- `Inno Setup Messages (5.5.3) (u)` — message block marker
- `TSetupHeader` — Inno setup header structure
- `TSetupLanguageEntry=` — language entry structure
- `TLZMA1SmallDecompressorS` — LZMA decompressor class
- `JLZMADecompSmall` — LZMA decompressor reference

The full Inno Setup command-line help text is also embedded, including `/SILENT`, `/VERYSILENT`, `/LOG`, `/NORESTART` and other installer flags — confirming a complete Inno Setup build.

### 2. Delphi Runtime Artifacts
Confirmed Delphi/Object Pascal compiler via:

- `FastMM Borland Edition (c) 2004 - 2008 Pierre le Riche` — Delphi memory manager
- `SOFTWARE\Borland\Delphi\RTL` — Delphi RTL registry key (UTF-16LE)
- `AnsiString`, `UnicodeString`, `TObject` — Delphi type system strings
- `AnsiChar`, `AnsiString` — Delphi character type markers
- Delphi exception strings: `Abstract Error`, `Access violation at address %p in module '%s'`

Ghidra analysis confirmed x86 Delphi entry point structure at `0x00411847`, calling a TLS initialization routine (`FUN_004065d4`) that resolves `GetModuleHandleW(0)` — standard Delphi runtime startup behavior.

### 3. Authenticode Forgery
The binary carries an embedded Authenticode signature that **fails verification** — message digest mismatch detected. The overlay contains certificate chain material from:

- **Piriform Software Ltd** (CCleaner vendor) — signed 2019–2022
- **Avast** — timestamp counter-signature chain
- **DigiCert** root and intermediate CA certificates

This multi-layered certificate embedding is a deliberate attempt to appear legitimate to casual inspection while the actual signature is invalid.

### 4. Overlay Structure
The majority of the file size exists beyond the final mapped PE section in an overlay region. This overlay contains:

- LZMA-compressed setup data (Inno Setup payload)
- Embedded certificate structures
- Multiple fake `MZ`-like structures within compressed data

This is the delivery mechanism — the actual IcedID payload or configuration is stored in the overlay and extracted at runtime by the Inno Setup decompressor.

### 5. Privilege and Process Indicators
Import table confirms dropper-class behavior:

- `OpenProcessToken`, `LookupPrivilegeValueW`, `AdjustTokenPrivileges` — privilege escalation
- `CreateProcessW` — child process spawning
- `CreateFileW`, `WriteFile`, `DeleteFileW` — file drop and cleanup
- `FindResourceW`, `LoadResource`, `LockResource` — embedded resource extraction
- `RegOpenKeyExW`, `RegQueryValueExW` — registry persistence checks

---

## Detection Logic

### Gate
```
uint16(0) == 0x5A4D    // MZ header
```

### Condition
```
( $inno_data and $inno_msg )                            // Both core Inno Setup markers required
2 of ($setup_hdr, $lang_ent, $lzma_cls, $jlzma)        // 2+ supporting Inno structure strings
( $freemake1 or $freemake2 )                            // Freemake decoy identity present
```

---

## False Positives / Limitations

**False positives:** Low. Legitimate Freemake or Inno Setup installers will not present a failed Authenticode signature. The combination of Inno Setup internals, Freemake identity, and embedded Piriform/Avast certificate material is specific to this dropper family.

**Limitations:** If a future variant changes the lure identity (different software masquerade) while keeping the Inno Setup framework, the `$freemake*` clause will not fire. The `$inno_data` and `$inno_msg` markers are version-specific to Inno Setup 5.5.x — a build using a different version would require updated version strings.

---

## How to Use
```bash
yara -s yara/MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike.yar <path_to_suspect_file_or_directory>
```

# LibGDK Win32 2.24.28 (i386) — Sample Fingerprint (YARA)

## Artifacts
- Rule: `yara/win_libgdk_win32_2.24.28_i386_sample_fingerprint.yar`

## Summary
This YARA rule is a **strict fingerprint** for a specific Windows **x86 DLL** that self-identifies as:
- `libgdk-win32-2.0-0.dll` (GTK / GDK related)

This DLL has been observed **renamed and bundled** with malware. This rule is meant to match **this exact observed sample** (high confidence), not to generically detect malware families.

> Safety: Static analysis only. Do not execute unknown samples.

---

## Sample Details (Observed)
- **Original/claimed name (string evidence):** `libgdk-win32-2.0-0.dll`
- **Architecture:** x86 (i386)
- **File type:** PE DLL
- **Size:** 837,120 bytes
- **PE timestamp:** 0 (suspicious / commonly seen in repacked or manipulated builds)

### Hashes
- **SHA256:** 6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59
- **Import Hash (imphash):** a75bce97ca3ad49cfd36ed9cd9d13ddd

---

## Why this rule exists
This is a “**known-bad / known-bundled**” style detection:
- If this exact DLL shows up in an environment where it *should not* (weird directories, temp paths, user profile paths, loader-stagers, etc.), it’s a strong packaging indicator.
- It’s also useful for **lab validation** and for building a consistent detection library.

---

## Detection Logic (What the YARA rule checks)
The rule uses the `pe` module and matches a tight set of properties:

### PE-level fingerprinting
- Is a PE file and specifically a **DLL**
- x86 machine type (`MACHINE_I386`)
- Exact **filesize** match: `837120`
- PE **timestamp == 0**
- Exact section + export characteristics:
  - `number_of_sections == 10`
  - `number_of_exports == 730`
- Exact **imphash()** match

### String anchors (identity + behavior hints)
The rule requires:
- `libgdk-win32-2.0-0.dll` (ascii/wide)
- plus **2 of** the following:
  - `GIMP Drawing Kit` (wide)
  - `Updt` (ascii)
  - `Tdk_window_process_all_updates`
  - `Tdk_spawn_command_line_on_screen`

This combination helps avoid matches on random DLLs while still supporting the sample identity.

---

## False Positives / Limitations
### False positives
Possible but **unlikely**:
- A closely matching GTK/GDK DLL build with identical imports + size + exports could match.
- In a normal enterprise environment, seeing this DLL outside expected software install paths is still worth investigating.

### Limitations
This is **brittle by design**:
- If the attacker re-packs, strips exports, changes imports, or alters size, the fingerprint will break.
That’s fine because the intent is to match a specific observed sample.

---

## How to use
Example scan:
```bash
yara -s yara/win_libgdk_win32_2.24.28_i386_sample_fingerprint.yar <path_to_suspect_file_or_directory> ```

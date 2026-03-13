# IcedID Installer Stub (Freemake Decoy) — Static Detection

## Overview
This Windows PE32 GUI executable presents itself as **Freemake Video Converter** via VersionInfo, and includes explicit **Inno Setup** build comments. Static analysis indicates this is a **Delphi/Inno Setup installer stub** with LZMA-based setup structures and a large overlay region, consistent with an installer wrapper used to carry embedded payload or configuration data.

## File Identity
- SHA256: cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc
- File type: PE32 executable (GUI) Intel 80386
- Compiler/Language: Delphi (Object Pascal)
- Installer: Inno Setup module

## VersionInfo (claimed identity)
- CompanyName: Freemake
- FileDescription: Freemake Video Converter
- ProductName: Freemake Video Converter
- Comments: This installation was built with Inno Setup.

## Authenticode
- Signature verification: **Failed**
- Message digest mismatch detected

## Structural Observations
- Multiple standard PE sections present
- `.rsrc` section of normal size
- **Overlay detected**; most of the file size exists beyond the final mapped section
- Overlay contains compressed data and certificate-like structures

## Installer / Setup Indicators
Recovered strings and structures indicate Inno Setup internals:

- `Inno Setup Setup Data (5.5.7) (u)`
- `Inno Setup Messages (5.5.3) (u)`
- `TSetupHeader`
- `TSetupLanguageEntry=`
- `TLZMA1SmallDecompressorS`
- `JLZMADecompSmall`

These confirm the file is an **Inno Setup–based installer stub** using LZMA compression.

## Behavioral Signals (from imports)
Relevant imported APIs:

- Registry access:
  - `RegOpenKeyExW`
  - `RegQueryValueExW`
- Privilege adjustment:
  - `OpenProcessToken`
  - `LookupPrivilegeValueW`
  - `AdjustTokenPrivileges`
- File and process operations:
  - `CreateProcessW`
  - `CreateFileW`
  - `WriteFile`
  - `DeleteFileW`
- Resource handling:
  - `FindResourceW`
  - `LoadResource`
  - `LockResource`

These behaviors are consistent with an installer wrapper or dropper.

## Detection Logic
The YARA rule detects:

- A valid PE file
- Inno Setup setup-data markers
- LZMA and setup structure strings
- Optional Freemake decoy identity strings

This combination provides a **resilient detection** for this sample class while avoiding overly generic Inno Setup matches.

## Files
- Rule: `yara/MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike.yar`



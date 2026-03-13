# Pikabot Loader Analysis

## Overview
This sample appears to be a Windows malware loader associated with the Pikabot family.  
The binary contains a large encoded resource blob that does not present a valid PE structure when carved directly, indicating staged or obfuscated payload storage.

---

## Initial Observations
- File type: Windows PE executable
- Behavior: Loader with embedded encoded data
- Large resource blob extracted from `.rsrc` section
- Multiple fake `MZ` headers detected inside the blob
- No valid PE header found after structural checks

---

## Resource Blob Analysis
The extracted blob (`blob_111038.bin`) contained:

- Several `MZ` signatures at offsets:
  - `0x1298e`
  - `0x18afc`
  - `0x2f0a3`

However:

- `e_lfanew` values were invalid
- No `PE\0\0` signature located near expected offsets
- Indicates the data is **encoded or transformed**, not raw PE files

---

## Encoding Indicators
Within the blob:

- Repeated 16-byte marker observed:

  ## !cILryP$LsPSiLpN
- Appeared at regular intervals (0x11 spacing)
- Over 400 occurrences detected

This suggests:

- Structured encoded records
- Likely custom encoding or configuration storage
- Strong candidate for a unique detection anchor

---

## Decoding Attempts
The following transformations were tested:

- Single-byte XOR
- ADD/SUB transforms
- Bit rotations
- Bit reversal
- Nibble swaps
- NOT transforms

Results:

- No valid PE structure recovered
- No `PE\0\0` signature located after transformations

Conclusion:

- Payload likely uses:
  - Multi-byte key
  - Custom algorithm
  - Runtime-only decoding

---

## Detection Logic
The YARA rule focuses on:

- The repeated unique marker pattern
- Structural characteristics of the loader
- Encoded resource blob behavior

This approach provides:

- Stable detection
- Low false-positive risk
- Family-level behavioral coverage

---

## Files
- Rule: `MAL_Win32_Pikabot_Loader_UniqueMarker.yar`

---

## Analyst Notes
This sample demonstrates typical modern loader behavior:

- Encoded payload storage
- Fake PE header artifacts
- Custom transformation logic
- Staged execution model

The absence of a directly recoverable PE payload suggests:

- Runtime decoding
- Environment-dependent decryption
- Potential anti-analysis mechanisms





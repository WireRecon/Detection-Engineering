## Sample Identity (Latrodectus.exe Lab)

This sample was provided/labeled as `latrodectus.exe`, but static analysis strongly indicates it is a **Bitdefender Trufos component** (likely a renamed DLL).

Key identity indicators observed:
- Resource metadata:
  - `CompanyName`: **Bitdefender**
  - `ProductName`: **Bitdefender Antivirus**
  - `FileDescription`: **Trufos API**
  - `InternalName` / `OriginalFilename`: **TRUFOS.DLL**
- Developer artifacts:
  - Multiple build/source paths referencing `...\ARK23181_2\trufos_dll\*.c`
  - PDB reference: `...\Release\trufos.pdb`
- Export surface is consistent with a legitimate library (math/image-processing style exports):
  - `RBCalcAvgW`, `RBCalcMaxW`, `RBCalcMin`, `RBCalcSum`, `RBCalcDev`
  - `RBGrayscale`, `RBInvertColor`, `RBMonochrome`

Additional behavior-relevant static indicators (consistent with security tooling):
- Minifilter communication imports from `FLTLIB.DLL`:
  - `FilterConnectCommunicationPort`, `FilterSendMessage`, `FilterGetMessage`, `FilterReplyMessage`, `FilterLoad`
- IPC markers:
  - `\\pipe\\`, `\\BaseNamedObjects\\`, `_SrvRequestPresent`, `_srvToClient`, `_clientToSrv`
- Capability hints:
  - `SeLoadDriverPrivilege`
  - `\\\\.\\PhysicalDrive%d`

**Conclusion:** This file is best treated as **Bitdefender Trufos (TRUFOS.DLL) identification**, not as a confirmed Latrodectus loader, based on static-only evidence.

---

## Detection Strategy

A single YARA rule was created to **identify Bitdefender Trufos component(s)** using a resilient cluster of:
- Dev/build artifacts (PDB + build path fragments)
- Distinctive export name surface (RB* functions)
- Supporting vendor metadata (with additional minifilter comms signals in the fallback path)

---

### Rule: Trufos Component Identification
**File:**  
`GEN_WIN_Bitdefender_Trufos_DLL.yar`

**Purpose:**  
Identifies Bitdefender Trufos user-mode component (TRUFOS.DLL) via dev artifacts and distinctive export surface.

**Key detection features:**
- `ARK23181_2` + `\trufos_dll\` + `trufos.pdb` (dev artifacts)
- RB* export cluster (`RBCalc*`, `RBGrayscale`, `RBInvertColor`, etc.)
- Vendor strings (`Bitdefender`, `Trufos API`, `TRUFOS.DLL`)
- Supporting minifilter comms imports (`Filter*Message`, `FilterConnectCommunicationPort`) used in the fallback path

**Detection logic:**
- PE x64 and DLL characteristic
- Requires either:
  - 2 of (dev artifacts) + strong RB* export cluster, OR
  - 2 of (vendor metadata) + strong RB* export cluster + 2 FLTLIB comms imports

---

## Indicators / Fingerprints

- SHA256: `aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c`
- MD5: `da8ae8e1de522b20a462239c6893613e`
- imphash: `dad9f669bb19a6ea9c2b335d7292cfc7`
- PE TimeDateStamp: `2022-04-13` (from 0x62576057)

---

## Testing Methodology
All testing was performed using **static analysis only**.

### Rule test (target sample)
Command:
```bash
yara -w GEN_WIN_Bitdefender_Trufos_DLL.yar latrodectus.exe

```
### False-positive sanity check (benign-ish)
Command:
```bash
yara -r -w GEN_WIN_Bitdefender_Trufos_DLL.yar /usr/lib/

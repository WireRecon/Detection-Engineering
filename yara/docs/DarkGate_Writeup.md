
These export sets suggest:
- DLLs are masquerading as legitimate Windows system libraries
- Intended to blend into the WindowsApps directory
- Likely used as staged payload components

---

## Detection Strategy

Two YARA rules were created to detect different stages of the infection chain.

---

### Rule 1: Loader Detection
**File:**  
`MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.yar`

**Purpose:**
Detects the initial loader executable.

**Key detection features:**
- WindowsApps drop paths
- Resource extraction function strings
- Rundll32 execution chain
- CDN/module path artifacts

**Detection logic:**
- PE x64 GUI binary
- Multiple WindowsApps drop indicators
- Execution strings
- CDN or module path artifacts

---

### Rule 2: Payload DLL Detection
**File:**  
`MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade.yar`

**Purpose:**
Detects embedded or dropped DLL payloads masquerading as system libraries.

**Key detection features:**
- Cryptbase-style `SystemFunction00x` exports
- WLDP-style export names
- x64 DLL characteristic

**Detection logic:**
Matches:
- Strong cryptbase export set, or
- Strong WLDP export set, or
- Both export families simultaneously

---

## Relationship Between the Two Rules
The rules are designed to work together:

| Stage | File Type | Detection Rule |
|------|-----------|----------------|
| Stage 1 | Loader EXE | Loader rule |
| Stage 2 | Embedded/dropped DLL | Payload DLL rule |

This creates a **multi-stage detection approach**:
- Rule 1 identifies the initial dropper.
- Rule 2 identifies the staged payload components.

---

## Testing Methodology
All testing was performed using static analysis only.

### Loader rule test
Command:
```bash
yara -w MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.yar darkgate.exe

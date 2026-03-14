# MAL_WIN_HTA_AdobeUpdater_Lab_Dropper — Detection Rule (YARA)

## Artifacts
- Rule: `yara/MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.yar`

## Summary
Lab-authored HTA dropper that masquerades as **Adobe Acrobat Updater**. The file is a fully functional Windows HTML Application (`.hta`) that presents a convincing fake update UI — including a social engineering MsgBox prompt, animated progress bar, and Adobe branding — while silently delivering a PowerShell TCP reverse shell and writing a persistence entry to the HKCU Run key. This sample was purpose-built to demonstrate HTA-based initial access and persistence techniques.

> **Note:** This is a lab-authored sample with a private lab C2 IP (`192.168.78.129:443`). The rule is included in this repository as a reference detection for this technique class.

---

## Sample Details
- **Filename:** `AdobeUpdater.hta`
- **Type:** Windows HTML Application (HTA) — VBScript + JavaScript
- **Masquerade identity:** Adobe Acrobat Updater
- **C2:** `192.168.78.129:443` (lab environment)
- **Analysis scope:** Source code review (lab-authored)

---

## Observed Behaviors

### 1. Adobe Acrobat Updater Masquerade
The HTA presents a fully crafted fake update interface:

- Window title: `Adobe Acrobat Updater`
- HTA application name: `Adobe Acrobat Updater`
- Fake icon reference: `adobe.ico`
- Social engineering MsgBox: `"Adobe Acrobat Updater: Click OK to install critical security updates."`
- Animated progress bar filling to 100% before closing the window with `"Update complete."`

The UI is designed to keep the user engaged and unsuspicious while the payload executes in the background.

### 2. PowerShell Reverse Shell
After the user clicks OK on the MsgBox, VBScript builds and executes a PowerShell reverse shell command:

- **Evasion flags:** `-ExecutionPolicy Bypass -WindowStyle Hidden`
- **Mechanism:** `System.Net.Sockets.TCPClient` connecting to `192.168.78.129:443`
- **Execution loop:** Reads commands from the socket, executes via `iex` (Invoke-Expression), returns output with current working directory prompt
- **Process:** Spawned via `WScript.Shell.Run` with window hidden (`0, False`)

### 3. HKCU Run Key Persistence
Before executing the reverse shell, the dropper writes itself to the Windows startup registry key:

- **Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value name:** `AdobeTaskHelper`
- **Data:** The full PowerShell reverse shell command

This ensures the reverse shell re-executes on every user login, maintaining persistent access across reboots without requiring elevated privileges.

### 4. Execution Flow
```
Window_OnLoad fires
  → Resize and center window
  → Show fake MsgBox (user clicks OK)
  → Build PowerShell reverse shell command string
  → Write persistence to HKCU Run key as AdobeTaskHelper
  → Execute reverse shell silently (window hidden)
  → Fake progress bar fills to 100%
  → Window closes after "Update complete."
```

---

## Detection Logic

### Condition
```
$hta_id                          // HTA application ID — "AdobeUpdater"
$hta_title                       // Masquerade title — "Adobe Acrobat Updater"
$persist                         // Persistence key name — "AdobeTaskHelper"
$run_key                         // HKCU Run registry path
$tcp_shell                       // PowerShell TCP reverse shell class
$ps_bypass                       // ExecutionPolicy Bypass evasion flag
1 of ($lure, $iex, $wsh,
       $regwrite, $ps_hidden)    // At least one additional supporting indicator
```

---

## Technique Mapping (MITRE ATT&CK)

| Technique | ID | Details |
|-----------|-----|---------|
| Phishing: Spearphishing Attachment | T1566.001 | HTA delivered as fake Adobe update |
| User Execution: Malicious File | T1204.002 | User opens and executes HTA |
| Command and Scripting: Visual Basic | T1059.005 | VBScript payload delivery |
| Command and Scripting: PowerShell | T1059.001 | Reverse shell via PowerShell |
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | HKCU Run key persistence |
| Obfuscated Files: Hidden Window | T1564.003 | `-WindowStyle Hidden` |
| Command and Control: Non-Standard Port | T1571 | TCP reverse shell on port 443 |

---

## False Positives / Limitations

**False positives:** None expected. The `AdobeTaskHelper` persistence key name combined with a PowerShell TCP reverse shell inside an HTA application is not present in legitimate software.

**Limitations:** If the persistence key name or masquerade title is changed, the rule will not fire. The rule is intentionally tight to this specific sample and serves as a reference detection for this technique class.

---

## How to Use
```bash
yara -s yara/MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.yar <path_to_suspect_file_or_directory>
```

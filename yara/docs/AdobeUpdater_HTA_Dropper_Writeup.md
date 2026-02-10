## Detection Engineering

A YARA rule was developed to detect the HTA dropper used in this lab.

Rule:
- `MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.yar`

This rule detects:
- HTA application markers
- WScript.Shell execution
- Hidden PowerShell execution
- Run-key persistence
- TCPClient reverse shell pattern

Full technical write-up:
See the Detection Engineering repository:
https://github.com/<WireRecon>/Detection-Engineering/tree/main/yara/docs

rule MAL_WIN_HTA_AdobeUpdater_Lab_Dropper
{
  meta:
    description = "Detects a lab-authored HTA dropper masquerading as Adobe Acrobat Updater. Delivers a PowerShell TCP reverse shell and establishes persistence via HKCU Run key (AdobeTaskHelper)."
    author = "WireRecon"
    date = "2026-02-12"
    reference = "Lab-authored sample — internal"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "None expected. The AdobeTaskHelper persistence key name combined with a PowerShell TCP reverse shell inside an HTA is not present in legitimate software."

  strings:
    // HTA application identity (masquerade)
    $hta_id     = "AdobeUpdater" ascii
    $hta_title  = "Adobe Acrobat Updater" ascii

    // Social engineering lure
    $lure       = "Adobe Acrobat Updater: Click OK to install critical security updates." ascii

    // Persistence registry key name — unique to this sample
    $persist    = "AdobeTaskHelper" ascii

    // PowerShell execution evasion flags
    $ps_bypass  = "ExecutionPolicy Bypass" ascii
    $ps_hidden  = "WindowStyle Hidden" ascii

    // Reverse shell mechanism
    $tcp_shell  = "System.Net.Sockets.TCPClient" ascii
    $iex        = "iex $d 2>&1 | Out-String" ascii

    // WScript.Shell object for execution and registry write
    $wsh        = "WScript.Shell" ascii
    $regwrite   = "RegWrite" ascii

    // HKCU Run key persistence path
    $run_key    = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii

  condition:
    // HTA file identifier
    $hta_id and

    // Must show the masquerade identity
    $hta_title and

    // Must have persistence mechanism
    $persist and
    $run_key and

    // Must have PowerShell reverse shell execution
    $tcp_shell and
    $ps_bypass and

    // At least one additional supporting indicator
    1 of ($lure, $iex, $wsh, $regwrite, $ps_hidden)
}

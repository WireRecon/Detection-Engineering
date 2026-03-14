import "pe"

rule MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade
{
  meta:
    description = "Detects DarkGate-related payload DLLs masquerading as Windows system libraries (cryptbase.dll / wldp.dll) via characteristic export-name sets. Dropped into WindowsApps by the DarkGate loader."
    author = "WireRecon"
    date = "2026-02-09"
    reference = "https://bazaar.abuse.ch/sample/056286b15e58ccc9f77873ef22c42e3b098860940990dbb7543e7f469ce7a2f6"
    hash_sha256 = "056286b15e58ccc9f77873ef22c42e3b098860940990dbb7543e7f469ce7a2f6"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Low. Legitimate cryptbase.dll and wldp.dll will not appear together or outside their expected system paths. Investigate any match outside System32."

  strings:
    // cryptbase masquerade export names (high signal)
    $cb1  = "SystemFunction001" ascii
    $cb2  = "SystemFunction002" ascii
    $cb3  = "SystemFunction003" ascii
    $cb4  = "SystemFunction004" ascii
    $cb5  = "SystemFunction005" ascii
    $cb6  = "SystemFunction028" ascii
    $cb7  = "SystemFunction029" ascii
    $cb8  = "SystemFunction034" ascii
    $cb9  = "SystemFunction036" ascii
    $cb10 = "SystemFunction040" ascii
    $cb11 = "SystemFunction041" ascii

    // wldp masquerade export names (high signal)
    $w1 = "WldpAddDeveloperCertificateForDynamicCodeTrust" ascii
    $w2 = "WldpQueryWindowsLockdownMode" ascii
    $w3 = "WldpQuerySecurityPolicy" ascii
    $w4 = "WldpSetDynamicCodeTrust" ascii
    $w5 = "WldpSetDynamicCodeTrust2" ascii
    $w6 = "WldpIsDynamicCodePolicyEnabled" ascii
    $w7 = "WldpIsAppApprovedByPolicy" ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.machine == pe.MACHINE_AMD64 and
    (pe.characteristics & 0x2000) != 0 and
    (
      (7 of ($cb*) and 4 of ($w*)) or
      (7 of ($cb*) and not (1 of ($w*))) or
      (4 of ($w*) and not (1 of ($cb*)))
    )
}

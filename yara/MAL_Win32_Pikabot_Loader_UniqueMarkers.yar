import "pe"

rule MAL_Win32_Pikabot_Loader_UniqueMarkers {
  meta:
    description = "Detects Pikabot loader via unique crypto marker and build artifacts (Qihoo 360 File Smasher masquerade)"
    author = "WireRecon"
    date = "2026-02-12"
    tlp = "WHITE"
    hash = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"

  strings:
    // Unique marker observed many times in the sample
    $crypto_marker = "!cILryP$LsPSiLpN" ascii

    // Campaign/master key identifier (verify it truly exists in sample)
    $campaign_id = "1F7BB2575E4D2D1B4F8FE32D1E6F53B87C981C61D3BFFA01" ascii

    // Build artifacts
    $pdb_1 = "vmagent_new\\bin\\joblist\\" ascii
    $pdb_2 = "QHFileSmasher.pdb" ascii

  condition:
    pe.is_pe and
    filesize < 3MB and
    (
      $campaign_id or
      #crypto_marker > 20 or
      all of ($pdb_*)
    )
}

rule MAL_Win32_Pikabot_Loader_BehaviorCluster {
  meta:
    description = "Detects Pikabot loader via Qihoo 360 masquerade + anti-360 artifacts + WININET network capability"
    author = "WireRecon"
    date = "2026-02-12"
    tlp = "WHITE"
    hash = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"

  strings:
    // Version resource masquerade cluster
    $ver_company  = "Qihoo 360 Technology Co. Ltd." wide
    $ver_product  = "File Smasher Application" wide
    $ver_internal = "QHFileSmasher" wide

    // Anti-360 Security evasion / artifacts
    $av_config_1 = "block_driver_root=true" ascii
    $av_config_2 = "block_ts_install_path=true" ascii
    $av_driver_1 = "360FsFlt.sys" ascii
    $av_driver_2 = "360SelfProtection.sys" ascii
    $av_driver_3 = "360AvFlt" ascii

    // System manipulation
    $sys_sc    = "sc.exe" ascii nocase
    $sys_reg_1 = "Software\\360Safe\\Liveup" ascii
    $sys_reg_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards" ascii

    // Network-ish artifacts
    $net_useragent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" wide
    $net_path      = "\\360TotalSecurity" ascii wide

  condition:
    pe.is_pe and
    filesize < 3MB and

    // Masquerade must be strong
    2 of ($ver_*) and

    // Must show clear 360 targeting/evasion
    3 of ($av_*) and

    // Either network strings OR system manipulation
    (1 of ($net_*) or 2 of ($sys_*)) and

    // Must actually have WININET entrypoints
    (
      pe.imports("WININET.dll", "InternetOpenW") or
      pe.imports("WININET.dll", "InternetOpenUrlW")
    ) and

    // Prefer unsigned binaries (simple + portable)
    pe.number_of_signatures == 0
}
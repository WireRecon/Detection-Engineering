import "pe"

rule MAL_Win32_Pikabot_Loader_BehaviorCluster
{
  meta:
    description = "Detects Pikabot loader via Qihoo 360 File Smasher version resource masquerade, anti-360 AV evasion artifacts, and WININET network capability"
    author = "WireRecon"
    date = "2026-02-12"
    reference = "https://bazaar.abuse.ch/sample/7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    hash_sha256 = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Low. Legitimate Qihoo 360 software will not contain anti-360 driver blocking configs or WININET C2 communication patterns. Unsigned binaries matching this cluster should be investigated."

  strings:
    // Version resource masquerade cluster (UTF-16)
    $ver_company  = "Qihoo 360 Technology Co. Ltd." wide
    $ver_product  = "File Smasher Application" wide
    $ver_internal = "QHFileSmasher" wide

    // Anti-360 security evasion / driver blocking configs (UTF-16LE in .rsrc XML config)
    $av_config_1 = "block_driver_root=true" wide
    $av_config_2 = "block_ts_install_path=true" wide
    $av_driver_1 = "360FsFlt.sys" wide
    $av_driver_2 = "360SelfProtection.sys" wide
    $av_driver_3 = "360AvFlt" wide

  condition:
    pe.is_pe and
    filesize < 3MB and
    2 of ($ver_*) and
    3 of ($av_*) and
    (
      pe.imports("WININET.dll", "InternetOpenW") or
      pe.imports("WININET.dll", "InternetOpenUrlW")
    ) and
    pe.number_of_signatures == 0
}

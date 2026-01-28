rule MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer
{
  meta:
    description = ".NET AsyncRAT-like sample with plugin framework, hosts/proxy tampering, and wallet/discord token artifacts"
    author = "WireRecon"
    date = "2026-01-27"
    reference = "Lab sample: asyncrat.exe"
    hash_sha256 = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"

  strings:
    // High-signal markers (UTF-16)
    $s1 = "DicordTokens" wide
    $s2 = "WDExclusion" wide
    $s3 = "KillProxy" wide
    $s4 = "ResetHosts" wide
    $s5 = "\\hosts.backup" wide
    $s6 = "AVRemoval.Class1" wide
    $s7 = "BackProxy.Class1" wide
    $s8 = "Plugin.Plugin" wide
    $s9 = "Msgpack" wide

    // Path indicators (UTF-16)
    $p1 = "\\drivers\\etc" wide
    $p2 = "\\Mozilla\\Firefox\\Profiles" wide
    $p3 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" wide

    // Lightweight .NET hint (common in .NET PEs)
    $dn1 = "mscoree.dll" ascii
    $dn2 = "_CorExeMain" ascii

  condition:
    // Cheap checks first
    uint16(0) == 0x5A4D and
    filesize == 64512 and

    // .NET-ish gate
    all of ($dn*) and

    // Require multiple independent capability markers
    5 of ($s*) and
    1 of ($p*)
}

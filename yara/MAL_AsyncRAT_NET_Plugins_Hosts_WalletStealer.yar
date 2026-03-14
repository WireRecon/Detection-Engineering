import "pe"

rule MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer
{
  meta:
    description = ".NET AsyncRAT-like sample with plugin framework, persistence (Run/schtasks), hosts/proxy tampering, and wallet/Discord token theft artifacts"
    author = "WireRecon"
    date = "2026-02-06"
    reference = "https://bazaar.abuse.ch/sample/8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    hash_sha256 = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    c2_decrypted = "winscapmarzo.duckdns.org:9003"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Unlikely; combination of plugin framework, hosts tampering, and wallet theft artifacts is highly specific"

  strings:
    // Capability / plugin markers (UTF-16 in .NET)
    $cap1  = "DicordTokens" wide
    $cap2  = "WDExclusion" wide
    $cap3  = "KillProxy" wide
    $cap4  = "ResetHosts" wide
    $cap5  = "\\hosts.backup" wide
    $cap6  = "AVRemoval.Class1" wide
    $cap7  = "BackProxy.Class1" wide
    $cap8  = "Plugin.Plugin" wide
    $cap9  = "Msgpack" wide
    $cap10 = "sendPlugin" wide
    $cap11 = "savePlugin" wide

    // Persistence indicators seen in NormalStartup.Install() (UTF-16)
    $per1 = "/c schtasks /create /f /sc onlogon /rl highest" wide
    $per2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
    $per3 = "@echo off" wide
    $per4 = "timeout 3 > NUL" wide

    // Path / wallet-extension indicators (UTF-16)
    $path1 = "\\drivers\\etc" wide
    $path2 = "\\Mozilla\\Firefox\\Profiles" wide
    $path3 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" wide

  condition:
    uint16(0) == 0x5A4D and
    pe.imports("mscoree.dll", "_CorExeMain") and
    6 of ($cap*) and
    1 of ($path*) and
    2 of ($per*)
}

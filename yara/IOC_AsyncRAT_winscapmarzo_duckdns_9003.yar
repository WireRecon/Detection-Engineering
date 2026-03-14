import "pe"

rule IOC_AsyncRAT_winscapmarzo_duckdns_9003
{
  meta:
    description = "Tight IOC fingerprint for AsyncRAT sample whose decrypted config resolves to C2 winscapmarzo.duckdns.org:9003 — matches on AES-encrypted config blobs extracted from Settings.cs"
    author = "WireRecon"
    date = "2026-02-06"
    reference = "https://bazaar.abuse.ch/sample/8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    hash_sha256 = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    c2_decrypted = "winscapmarzo.duckdns.org:9003"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Negligible; these are AES-encrypted config blobs unique to this build"

  strings:
    // AES-encrypted base64 config blobs from Settings.cs
    // Decrypt to: Hosts=winscapmarzo.duckdns.org, Ports=9003
    $cfg1 = "molsALSskPbUTZ7jlKWTjfGDqSV2KW6t5Gpg0dLainA21nkV3TAAGJhYUP5M7mS6h1qQ3upEl7D0Kyme/r7dQrqMQI0by/7k3fGwLBhe9hQ=" ascii wide
    $cfg2 = "vplU0S/EjXVyiAwA9ani6sNIIfGHF/Jo2xTcgVhFzkqmwfQB1O0/CawkQIVvF00NKc6TgF3QHQftneQzkuDrCA==" ascii wide
    $cfg3 = "RUgzNXc1cFVFQTNFSGl3MzcxbGFjVzlUZXNpcUU5YlE=" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    pe.imports("mscoree.dll", "_CorExeMain") and
    2 of ($cfg*)
}

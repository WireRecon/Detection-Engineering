rule IOC_AsyncRAT_winscapmarzo_duckdns_9003
{
  meta:
    description = "IOC rule for specific AsyncRAT lab sample C2"
    author = "WireRecon"
    date = "2026-02-07"
    c2 = "winscapmarzo.duckdns.org:9003"
    note = "Static config-derived; sample uses TLS with certificate pinning"

  strings:
    $c2 = "winscapmarzo.duckdns.org" ascii wide
    $p  = "9003" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    $c2 and $p
}

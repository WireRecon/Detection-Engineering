import "pe"

rule MAL_Win32_Pikabot_Loader_UniqueMarkers
{
  meta:
    description = "Detects Pikabot loader via unique repeated crypto marker in .rsrc section and build artifacts from Qihoo 360 File Smasher masquerade"
    author = "WireRecon"
    date = "2026-02-12"
    reference = "https://bazaar.abuse.ch/sample/7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    hash_sha256 = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Unlikely. The repeated crypto marker at 0x11 spacing with 20+ occurrences in .rsrc is specific to this loader build. PDB path artifacts further reduce false positive risk."

  strings:
    // Unique 16-byte crypto marker — observed 400+ times in .rsrc at 0x11 spacing
    $crypto_marker = "!cILryP$LsPSiLpN" ascii

    // Build artifacts from Qihoo 360 File Smasher masquerade
    $pdb_1 = "vmagent_new\\bin\\joblist\\" ascii
    $pdb_2 = "QHFileSmasher.pdb" ascii

  condition:
    pe.is_pe and
    filesize < 3MB and
    (
      #crypto_marker > 20 or
      all of ($pdb_*)
    )
}

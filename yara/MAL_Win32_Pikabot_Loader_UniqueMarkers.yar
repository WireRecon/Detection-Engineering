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
    false_positives = "Unlikely for the crypto_marker branch; 20+ occurrences at 0x11 spacing in .rsrc is highly specific to this loader build. PDB branch is broader — vmagent_new\\bin\\joblist\\ is a partial path fragment that could match other binaries from the same dev environment that are not Pikabot loaders; treat PDB-only matches as lower confidence pending additional context."

  strings:
    /* Unique 16-byte crypto marker — observed 400+ times in .rsrc at 0x11 spacing */
    $crypto_marker = "!cILryP$LsPSiLpN" ascii

    /* Partial path fragment — could match other builds from the same dev environment that are not Pikabot loaders; PDB branch alone is lower confidence */
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

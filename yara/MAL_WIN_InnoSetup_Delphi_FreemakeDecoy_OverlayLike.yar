rule MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike
{
  meta:
    description = "Detects a Delphi/Inno Setup installer stub with LZMA setup-data markers and Freemake Video Converter decoy identity. Authenticode signature present but verification fails. Overlay-heavy structure consistent with embedded payload."
    author = "WireRecon"
    date = "2026-02-12"
    reference = "https://bazaar.abuse.ch/sample/cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    hash_sha256 = "cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Low. Legitimate Inno Setup installers will not present a failed Authenticode signature or combine Freemake identity with Piriform/Avast certificate chains in the overlay."

  strings:
    // Core Inno Setup markers (high signal — confirmed in FLOSS static strings)
    $inno_data = "Inno Setup Setup Data (5.5.7) (u)" ascii wide
    $inno_msg  = "Inno Setup Messages (5.5.3) (u)" ascii wide

    // Inno internal structures / LZMA decompressor (supporting)
    $setup_hdr = "TSetupHeader" ascii wide
    $lang_ent  = "TSetupLanguageEntry=" ascii wide
    $lzma_cls  = "TLZMA1SmallDecompressorS" ascii wide
    $jlzma     = "JLZMADecompSmall" ascii wide

    // Decoy identity strings (confirmed in FLOSS VersionInfo section)
    $freemake1 = "Freemake Video Converter" ascii wide
    $freemake2 = "This installation was built with Inno Setup." ascii wide

  condition:
    uint16(0) == 0x5A4D and
    ( $inno_data and $inno_msg ) and
    ( 2 of ($setup_hdr, $lang_ent, $lzma_cls, $jlzma) ) and
    ( $freemake1 or $freemake2 )
}

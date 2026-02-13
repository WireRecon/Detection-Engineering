rule MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike
{
  meta:
    description = "Detects a Delphi/Inno Setup installer stub with LZMA setup-data markers and Freemake Video Converter decoy identity (lab sample; overlay-heavy Inno payload likely present)"
    author = "Mark Twain (with ChatGPT)"
    date = "2026-02-12"
    reference = "Lab static analysis: Inno Setup 5.5.x markers + Delphi strings + Freemake VersionInfo decoy"
    tlp = "WHITE"

  strings:
    // Core Inno Setup markers (high signal)
    $inno_data = "Inno Setup Setup Data (5.5.7) (u)" ascii wide
    $inno_msg  = "Inno Setup Messages (5.5.3) (u)" ascii wide
    $inno_desc = "<description>Inno Setup</description>" ascii wide

    // Inno internal structures / LZMA usage (supporting)
    $setup_hdr = "TSetupHeader" ascii wide
    $lang_ent  = "TSetupLanguageEntry=" ascii wide
    $lzma_cls  = "TLZMA1SmallDecompressorS" ascii wide
    $jlzma     = "JLZMADecompSmall" ascii wide

    // Decoy identity (supporting, not required alone)
    $freemake1 = "Freemake Video Converter" ascii wide
    $freemake2 = "This installation was built with Inno Setup." ascii wide

  condition:
    uint16(0) == 0x5A4D and
    // Require strong Inno markers
    ( $inno_data and $inno_msg ) and
    // Plus at least two supporting indicators
    ( 2 of ($setup_*, $lang_ent, $lzma_*, $jlzma, $inno_desc) ) and
    // Optional decoy identity (tightens to this sample family)
    ( $freemake1 or $freemake2 )
}

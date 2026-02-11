import "pe"

rule GEN_WIN_Bitdefender_Trufos_DLL
{
  meta:
    description = "Identifies Bitdefender Trufos user-mode component (TRUFOS.DLL) via dev artifacts + export surface + minifilter comms indicators; static-only classification."
    author = "WireRecon"
    date = "2026-02-11"
    reference = "Internal static analysis: Trufos API / Bitdefender metadata, trufos.pdb, trufos_dll source paths, distinctive RB* exports"
    tlp = "WHITE"

  strings:
    /* Strong dev artifacts (highly specific) */
    $pdb_trufos      = "trufos.pdb" ascii
    $path_trufos_dll = "\\trufos_dll\\" ascii
    $ark_build       = "ARK23181_2" ascii

    /* Vendor metadata (usually in resources) */
    $bd_vendor       = "Bitdefender" wide
    $trufos_api      = "Trufos API" wide
    $orig_trufos     = "TRUFOS.DLL" wide

    /* Distinctive export name surface (library-like) */
    $exp_calcavgw    = "RBCalcAvgW" ascii
    $exp_calcmaxw    = "RBCalcMaxW" ascii
    $exp_calcmin     = "RBCalcMin"  ascii
    $exp_calcsum     = "RBCalcSum"  ascii
    $exp_calcdev     = "RBCalcDev"  ascii
    $exp_gray        = "RBGrayscale" ascii
    $exp_invert      = "RBInvertColor" ascii
    $exp_mono        = "RBMonochrome" ascii

    /* Supporting behavior (not primary; can exist in legit security tools) */
    $imp_filter_connect = "FilterConnectCommunicationPort" ascii
    $imp_filter_send    = "FilterSendMessage" ascii
    $imp_filter_get     = "FilterGetMessage" ascii
    $imp_filter_reply   = "FilterReplyMessage" ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.is_pe and
    pe.machine == pe.MACHINE_AMD64 and
    pe.characteristics & pe.DLL and

    /* Require core Trufos identification */
    (
      /* dev artifacts strongly identify this component */
      ( 2 of ($pdb_trufos, $path_trufos_dll, $ark_build) )
      and
      /* plus distinctive RB* export surface */
      ( 5 of ($exp_*) )
    )
    or
    (
      /* fallback: vendor metadata + export surface */
      ( 2 of ($bd_vendor, $trufos_api, $orig_trufos) )
      and
      ( 5 of ($exp_*) )
    )
    and
    /* optional supporting minifilter comms cluster (do not require; reduces brittleness) */
    ( 0 of ($imp_filter_*) or true )
}

import "pe"

rule GEN_WIN_Bitdefender_Trufos_DLL
{
  meta:
    description = "Identifies Bitdefender Trufos user-mode component (TRUFOS.DLL) via dev artifacts, RB* export surface, and Trufos-specific IPC/runtime markers. Sample observed renamed as latrodectus.exe."
    author = "WireRecon"
    date = "2026-02-11"
    reference = "https://bazaar.abuse.ch/sample/aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    hash_sha256 = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    hash_md5 = "da8ae8e1de522b20a462239c6893613e"
    hash_imphash = "dad9f669bb19a6ea9c2b335d7292cfc7"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Low. Legitimate TRUFOS.DLL in its expected Bitdefender installation path is benign. Any match outside a Bitdefender install directory warrants investigation."

  strings:
    /* Dev/build artifacts (highly specific) */
    $dev_pdb         = "trufos.pdb" ascii
    $dev_trufos_dll  = "\\trufos_dll\\" ascii
    $dev_build_id    = "ARK23181_2" ascii

    /* Vendor metadata (resources) */
    $vnd_bitdefender = "Bitdefender" wide
    $vnd_trufos_api  = "Trufos API" wide
    $vnd_trufos_dll  = "TRUFOS.DLL" wide

    /* Export name surface (distinctive RB* cluster) */
    $exp1 = "RBCalcAvgW" ascii
    $exp2 = "RBCalcMaxW" ascii
    $exp3 = "RBCalcMin"  ascii
    $exp4 = "RBCalcSum"  ascii
    $exp5 = "RBCalcDev"  ascii
    $exp6 = "RBGrayscale" ascii
    $exp7 = "RBInvertColor" ascii
    $exp8 = "RBMonochrome" ascii

    /* Trufos-specific IPC / runtime markers (confirmed via FLOSS) */
    $trf1 = "TRFCOMMPORT" wide
    $trf2 = "Global\\Trf01" wide
    $trf3 = "\\Systemroot\\TrfDefData.tmp" wide
    $trf4 = "TrfArc" wide

    /* Minifilter comms API imports */
    $flt1 = "FilterConnectCommunicationPort" ascii
    $flt2 = "FilterSendMessage" ascii
    $flt3 = "FilterGetMessage" ascii
    $flt4 = "FilterReplyMessage" ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.is_pe and
    pe.machine == pe.MACHINE_AMD64 and
    (pe.characteristics & pe.DLL) != 0 and
    (
      /* Primary: dev artifacts + RB* export surface */
      (
        2 of ($dev_*) and
        5 of ($exp*)
      )
      or
      /* Secondary: vendor metadata + RB* export surface + Trufos IPC markers */
      (
        2 of ($vnd_*) and
        5 of ($exp*) and
        2 of ($trf*)
      )
      or
      /* Fallback: vendor metadata + RB* export surface + minifilter comms */
      (
        2 of ($vnd_*) and
        5 of ($exp*) and
        2 of ($flt*)
      )
    )
}

import "pe"

rule MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper
{
  meta:
    description = "Detects a Windows x64 loader/dropper that extracts embedded resources to WindowsApps, launches staged DLL via rundll32, and includes CDN module path artifacts. Masquerades as Microsoft ApiSet Stub DLL."
    author = "WireRecon"
    date = "2026-02-09"
    reference = "https://bazaar.abuse.ch/sample/056286b15e58ccc9f77873ef22c42e3b098860940990dbb7543e7f469ce7a2f6"
    hash_sha256 = "056286b15e58ccc9f77873ef22c42e3b098860940990dbb7543e7f469ce7a2f6"
    confidence = "high"
    tlp = "CLEAR"
    false_positives = "Unlikely. Would require a PE x64 GUI binary containing WindowsApps drop paths, extract_resource_to_file patterns, and cleanmgr/rundll32 execution strings simultaneously."

  strings:
    // C2 staging / CDN module path artifacts (high signal)
    $stage1 = "cdn3-adb1.online" wide
    $mod1   = "abdwufkw/modules/cleanhelper.png" wide
    $mod2   = "abdwufkw/modules/runsysclean.png" wide
    $mod3   = "abdwufkw/modules/legacy_l1.png" wide

    // Resource extraction + WindowsApps staging (high signal cluster)
    $drop1 = "\\..\\Local\\Microsoft\\WindowsApps\\cleanhelper.dll" ascii
    $drop2 = "\\..\\Local\\Microsoft\\WindowsApps\\runsysclean.dll" ascii
    $drop3 = "\\..\\Local\\Microsoft\\WindowsApps\\cryptbase.dll" ascii
    $drop4 = "\\..\\Local\\Microsoft\\WindowsApps\\wldp.dll" ascii
    $drop5 = "extract_resource_to_file(CLEANHELPER, full_path)" ascii
    $drop6 = "extract_resource_to_file(RUNSYSCLEAN, full_path)" ascii

    // Execution chain (very high signal)
    $exec1 = "C:\\windows\\system32\\cleanmgr.exe" ascii
    $exec2 = "rundll32 cleanhelper.dll T34 /k funtic321 1" ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.machine == pe.MACHINE_AMD64 and
    pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
    not pe.is_signed and
    3 of ($drop*) and
    1 of ($exec*) and
    ( $stage1 or 1 of ($mod*) )
}

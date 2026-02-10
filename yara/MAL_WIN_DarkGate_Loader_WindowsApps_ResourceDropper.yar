import "pe"

rule MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper
{
  meta:
    description = "Detects a Windows x64 loader/dropper that extracts embedded resources to WindowsApps, launches staged DLL via rundll32, and includes CDN module path artifacts"
    author = "WireRecon"
    date = "2026-02-09"
    reference = "Lab analysis: darkgate.exe (static); resource-dropper with WindowsApps staging + rundll32 execution"
    hash_sha256 = "ADD_SHA256_HERE"
    tlp = "white"

  strings:
    // Staging / module path artifacts (high signal)
    $stage1 = "cdn3-adb1.online" wide
    $mod1   = "abdwufkw/modules/cleanhelper.png" wide
    $mod2   = "abdwufkw/modules/runsysclean.png" wide
    $mod3   = "abdwufkw/modules/legacy_l1.png" wide

    // Resource extraction + WindowsApps staging (hsignaligh  cluster)
    $drop1 = "\\..\\Local\\Microsoft\\WindowsApps\\cleanhelper.dll" ascii
    $drop2 = "\\..\\Local\\Microsoft\\WindowsApps\\runsysclean.dll" ascii
    $drop3 = "\\..\\Local\\Microsoft\\WindowsApps\\cryptbase.dll" ascii
    $drop4 = "\\..\\Local\\Microsoft\\WindowsApps\\wldp.dll" ascii
    $drop5 = "extract_resource_to_file(CLEANHELPER, full_path)" ascii
    $drop6 = "extract_resource_to_file(RUNSYSCLEAN, full_path)" ascii

    // Execution chain (very high signal)
    $exec1 = "C:\\windows\\system32\\cleanmgr.exe" ascii
    $exec2 = "rundll32 cleanhelper.dll T34 /k funtic321 1" ascii

    // Optional anti-analysis indicators (don’t hard-require)

  condition:
    uint16(0) == 0x5A4D and
    pe.machine == pe.MACHINE_AMD64 and
    pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
    not pe.is_signed and

    3 of ($drop*) and
    1 of ($exec*) and
    ( $stage1 or 1 of ($mod*) )  
}

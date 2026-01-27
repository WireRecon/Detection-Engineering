import "pe"

rule WIN_LibGDK_Win32_2_24_28_i386_SampleFingerprint
{
  meta:
    description = "Fingerprints a Windows i386 DLL that self-identifies as GTK+ libgdk-win32-2.0-0.dll v2.24.28. This binary has been observed renamed in malicious bundles; use separate telemetry to detect unusual load/execution paths."
    author = "Michael"
    date = "2026-01-26"
    scope = "sample_fingerprint"
    false_positives = "Possible on closely matching GTK/GDK builds; intended for this observed sample."
    sha256 = "6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
    imphash = "a75bce97ca3ad49cfd36ed9cd9d13ddd"

  strings:
    $orig = "libgdk-win32-2.0-0.dll" ascii wide
    $desc = "GIMP Drawing Kit" wide
    $updt = "Updt" ascii
    $x1   = "Tdk_window_process_all_updates"
    $x2   = "Tdk_spawn_command_line_on_screen"

  condition:
    pe.is_pe and
    pe.is_dll() and
    pe.machine == pe.MACHINE_I386 and
    filesize == 837120 and
    pe.timestamp == 0 and
    pe.number_of_sections == 10 and
    pe.number_of_exports == 730 and
    pe.imphash() == "a75bce97ca3ad49cfd36ed9cd9d13ddd" and
    $orig and
    2 of ($desc, $updt, $x1, $x2)
}

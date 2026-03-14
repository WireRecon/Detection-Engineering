# YARA Rules

This folder contains YARA rules developed from static malware analysis, organized by malware family.

## Table of Contents
- [AsyncRAT (.NET)](#asyncrat-net)
- [Qbot Sample](#qbot-sample)
- [DarkGate Loader + Payload DLLs](#darkgate-loader--payload-dlls)
- [PikaBot Loader](#pikabot-loader)
- [Inno Setup / Delphi Installer Stub (Freemake Decoy)](#inno-setup--delphi-installer-stub-freemake-decoy)
- [Bitdefender Trufos Component](#bitdefender-trufos-component-lab-labeled-latrodectusexe)
- [HTA Dropper — Adobe Updater (Lab)](#hta-dropper--adobe-updater-lab)

---

## AsyncRAT (.NET)

- **MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer.yar**  
  Behavior-based detection for AsyncRAT-like samples using plugin framework, wallet theft, token harvesting, and hosts/proxy tampering artifacts.

- **IOC_AsyncRAT_winscapmarzo_duckdns_9003.yar**  
  Narrow IOC rule targeting the C2 for this specific AsyncRAT build.

See: `docs/MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer.md` for analysis notes.

---

## Qbot Sample

- **win_libgdk_win32_2_24_28_i386_sample_fingerprint.yar**  
  Strict fingerprint rule for a Windows x86 DLL self-identifying as `libgdk-win32-2.0-0.dll`, observed renamed and bundled with malicious tooling.

See: `docs/win_libgdk_win32_2_24_28_i386_sample_fingerprint.md` for analysis notes.

---

## DarkGate Loader + Payload DLLs

- **MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.yar**  
  Detects a Windows x64 loader/dropper that stages embedded resources into `WindowsApps` and launches a staged DLL via `rundll32`, with CDN module path artifacts and anti-VM indicators.

- **MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade.yar**  
  Detects DarkGate-related x64 payload DLLs masquerading as Windows system libraries (`cryptbase.dll` / `wldp.dll`) via characteristic export-name sets.

See: `docs/MAL_WIN_DarkGate_Loader_WindowsApps_ResourceDropper.md` and `docs/MAL_WIN_DarkGate_PayloadDLL_Cryptbase_Wldp_Masquerade.md` for analysis notes.

---

## PikaBot Loader

- **MAL_Win32_Pikabot_Loader_UniqueMarkers.yar**  
  Detects the PikaBot loader via a unique 16-byte crypto marker appearing 400+ times at regular intervals in the `.rsrc` section, and PDB build path artifacts from the Qihoo 360 File Smasher masquerade.

- **MAL_Win32_Pikabot_Loader_BehaviorCluster.yar**  
  Behavior-focused companion rule targeting the Qihoo 360 version resource masquerade identity, anti-360 AV driver blocking configuration, and confirmed WININET network capability.

See: `docs/MAL_Win32_Pikabot_Loader_UniqueMarkers.md` and `docs/MAL_Win32_Pikabot_Loader_BehaviorCluster.md` for analysis notes.

---

## Inno Setup / Delphi Installer Stub (Freemake Decoy)

- **MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike.yar**  
  Detects a Delphi/Inno Setup installer stub masquerading as Freemake Video Converter. Authenticode signature present but verification fails. Overlay-heavy structure consistent with embedded payload delivery.

See: `docs/MAL_WIN_InnoSetup_Delphi_FreemakeDecoy_OverlayLike.md` for analysis notes.

---

## Bitdefender Trufos Component (lab-labeled: latrodectus.exe)

- **GEN_WIN_Bitdefender_Trufos_DLL.yar**  
  Identifies the Bitdefender Trufos user-mode component (`TRUFOS.DLL`) via dev/build artifacts, a distinctive `RB*` export name cluster, and Trufos-specific IPC and runtime markers. Sample was observed delivered renamed as `latrodectus.exe`.

See: `docs/GEN_WIN_Bitdefender_Trufos_DLL.md` for analysis notes.

---

## HTA Dropper — Adobe Updater (Lab)

- **MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.yar**  
  Detects a lab-authored HTA dropper masquerading as Adobe Acrobat Updater. Delivers a PowerShell TCP reverse shell and establishes persistence via HKCU Run key (`AdobeTaskHelper`).

See: `docs/MAL_WIN_HTA_AdobeUpdater_Lab_Dropper.md` for analysis notes.

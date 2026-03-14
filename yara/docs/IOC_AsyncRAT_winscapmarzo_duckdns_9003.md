# IOC_AsyncRAT_winscapmarzo_duckdns_9003 — IOC Fingerprint Rule (YARA)

## Artifacts
- Rule: `yara/IOC_AsyncRAT_winscapmarzo_duckdns_9003.yar`
- Companion behavior rule: `yara/MAL_AsyncRAT_NET_Plugins_Hosts_WalletStealer.yar`

## Summary
Tight IOC fingerprint targeting a specific AsyncRAT build whose AES-encrypted configuration decrypts to C2 `winscapmarzo.duckdns.org:9003`. The rule matches on the raw base64-encoded config blobs extracted from `Settings.cs` in the .NET assembly — strings that are unique to this build and not present in generic AsyncRAT variants.

This rule is **intentionally brittle**: if the attacker recompiles with a different C2, the config blobs change and this rule will not fire. Use the companion MAL rule for broader variant coverage.

---

## Sample Details (Observed)
- **File:** `asyncrat.exe`
- **Type:** Windows PE32 (x86) .NET assembly (GUI)
- **Analysis scope:** Static only — sample was not executed

### Hashes
- **SHA256:** `8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb`

### Decrypted C2
- **Host:** `winscapmarzo.duckdns.org`
- **Port:** `9003`
- **Source:** AES-encrypted base64 blobs in `Settings.cs` — decrypted during static analysis

---

## Detection Logic

### Gate
```
uint16(0) == 0x5A4D                             // MZ header
pe.imports("mscoree.dll", "_CorExeMain")        // .NET assembly
```

### IOC Strings
Three AES-encrypted base64 config blobs from `Settings.cs`. These blobs decrypt to the C2 host, port, and build key for this specific sample. Requiring 2 of 3 allows a match even if one blob is partially overwritten or the file is slightly modified.

### Condition
```
2 of ($cfg*)    // at least 2 of the 3 AES config blobs must be present
```

---

## False Positives / Limitations

**False positives:** Negligible. These are AES-encrypted config values unique to this compiled build. They will not appear in legitimate software.

**Limitations:** This is a point-in-time fingerprint. Any recompile of AsyncRAT with a different C2 will produce different config blobs and will not be caught by this rule. This rule is best used for hunting known-bad infrastructure in retrospective log/file analysis, not as a general AsyncRAT detector.

---

## How to Use
```bash
yara -s yara/IOC_AsyncRAT_winscapmarzo_duckdns_9003.yar <path_to_suspect_file_or_directory>
```

AsyncRAT Sample Lab Summary (Static Analysis)
Sample details

File: asyncrat.exe

Type: Windows PE32 (x86) .NET assembly (GUI)

SHA256: 8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb

Safety constraint: Sample was not executed (static analysis only).

What we found (high-confidence behaviors)

The string set strongly indicates a modular remote-access tool (RAT) with stealer and defense-evasion features.

1) Modular/plugin framework + packed messaging

Evidence shows a plugin-based architecture and message packing:

Plugin.Plugin

sendPlugin, savePlugin, Plugins

Msgpack / MsgPack-related strings

This points to a RAT design where the operator can push modules (“plugins”) and exchange structured messages with the client.


2) Credential/token and crypto-wallet targeting

Multiple indicators suggest theft of credentials/tokens and wallet artifacts:

DicordTokens (Discord token theft artifact; notable misspelling)

WebBrowserPass, Password, Tokens

Browser profile/extension harvesting paths for Chrome/Brave/Edge (Local Extension Settings), including the MetaMask extension ID

Wallet-related markers (e.g., Exodus, Electrum, Ledger Live, ErgoWallet)

This is consistent with a stealer capability aimed at browser data and crypto wallets.


3) Defense evasion + system tampering

The sample contains strings associated with weakening defenses and modifying network behavior:

WDExclusion (Defender exclusion behavior)

KillProxy, BackProxy.Class1

Hosts file tampering indicators:

\drivers\etc

\hosts.backup

ResetHosts

127.0.0.1 Blocked!

Process manipulation / browser interference:

cmd.exe

/c taskkill.exe /im chrome.exe /f

These suggest attempts to alter network resolution/proxy settings and disrupt browser activity during theft or control.


4) Base64/crypto material present (no readable network IOCs)

Base64-encoded blobs exist and decode to raw bytes (likely keys/encrypted config), but did not yield readable URLs/domains/IPs via straightforward decoding. This suggests configuration or cryptographic material is embedded and may require decryption logic to interpret.


YARA detection approach

A YARA rule was built using multiple independent, high-signal strings rather than generic .NET or filename-based matches. The rule matches the sample based on the combined presence of:

plugin framework artifacts,

MsgPack usage,

Discord token theft marker,

Defender/proxy/hosts tampering artifacts,

and wallet/browser harvesting paths.

This combination reduces false positives because legitimate software is unlikely to contain this specific cluster of capabilities and paths.

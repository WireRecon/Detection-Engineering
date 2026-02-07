# AsyncRAT Sample Lab Summary (Static Analysis)

## Sample details
- **File:** `asyncrat.exe`
- **Type:** Windows PE32 (x86) .NET assembly (GUI)
- **SHA256:** `8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb`
- **Safety constraint:** The sample was **not executed** (static analysis only).

---

## What we found (high-confidence behaviors)
The extracted string set strongly indicates a **modular remote access tool (RAT)** with **stealer** and **defense-evasion** capabilities.

### 1) Modular/plugin framework + packed messaging
Evidence supports a plugin-based architecture and structured message exchange:
- `Plugin.Plugin`
- `sendPlugin`, `savePlugin`, `Plugins`
- `Msgpack` / MsgPack-related strings

This aligns with a RAT design where the operator can push modules (“plugins”) and exchange structured messages with the client.

### 2) Credential/token and crypto-wallet targeting
Indicators suggest theft of credentials/tokens and wallet-related artifacts:
- `DicordTokens` (Discord token theft artifact; notable misspelling)
- `WebBrowserPass`, `Password`, `Tokens`
- Browser profile/extension harvesting paths for Chrome/Brave/Edge (`Local Extension Settings`), including the MetaMask extension ID
- Wallet-related markers (e.g., Exodus, Electrum, Ledger Live, ErgoWallet)

This is consistent with stealer functionality aimed at browser data and cryptocurrency wallets.

### 3) Defense evasion + system tampering
Strings indicate attempts to weaken defenses and modify network behavior:
- `WDExclusion` (Defender exclusion behavior)
- `KillProxy`, `BackProxy.Class1`
- Hosts file tampering indicators:
  - `\drivers\etc`
  - `\hosts.backup`
  - `ResetHosts`
  - `127.0.0.1 Blocked!`
- Process manipulation / browser interference:
  - `cmd.exe`
  - `/c taskkill.exe /im chrome.exe /f`

T

<div align="center">

# nikke-k2f-check

**Find out in a minute whether the NIKKE PC launcher malware got you, and what to do in which order.**

English · [中文](README.md)

![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue) ![shell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE) ![license](https://img.shields.io/badge/license-MIT-green) ![incident](https://img.shields.io/badge/incident-2026--09--27~11--04-red)

[Player guide (zh-TW)](https://wizerdbache.github.io/nikke-k2f-check/) · [Quick start](#quick-start) · [Reading the verdict](#reading-the-verdict) · [Facts and sources](docs/FACTS.md) · [Developer doc](docs/DEVELOPER.md) · [For AI agents](AGENTS.md)

![First screen of the player guide: chapter list on the left, the title and the first section, for Delta Force players, on the right (labels in Traditional Chinese)](docs/assets/hero.png)

</div>

*Image labels are in Traditional Chinese; the player guide is written for Traditional Chinese readers.*

## Delta Force players: read this first

> **Delta Force in Taiwan, Hong Kong and Macau (the Garena edition) does not appear to be affected.** To be sure, run the [quick start](#quick-start); the checker finds the Garena launcher on its own.

- The tampered files sat on Level Infinite's own CDN. The Garena edition uses Garena's launcher, whose web content comes from Garena's sites, not from that CDN.
- The author checked their own Garena launcher (installed in August, last opened 09-09): its logs, web cache and binaries contain none of the tampered URLs, the 4 files or any K2F indicator.
- The circulating list of affected games refers to Delta Force **global / Steam**. From Taiwan without a VPN the author could only find the Garena edition, not the Steam one.
- Not verified: Garena launcher builds after 09-27 (the author did not update, to avoid the risk; the web host it used no longer resolves, so it cannot be compared online), and the global / Steam builds (none available to test).

## Wuthering Waves players

> **Wuthering Waves, both the official-launcher edition and the Steam edition, does not appear to be affected.**

- Some players guessed it was hit because Tencent holds a stake in Kuro Games and the game once worked with Level Infinite; no sample or log supports that claim.
- Its launcher is Kuro's own (binaries signed by KURO TECHNOLOGY (HONG KONG)), and the Steam edition starts from a Kuro-signed program too; neither is the tampered Level Infinite launcher. Its web view is Edge WebView2 (data in `%APPDATA%\KRLauncher`), not the one NIKKE uses.
- The author checked both editions on their own PC (both opened after 09-27, by folder timestamps): about 2,600 files in the install folders, `%APPDATA%\KRLauncher` and `LocalLow\kurogame`, searched byte by byte, contain none of the K2F domains, C2 addresses, malware file names or the tampered Level Infinite CDN hosts.
- The checker does not recognise the Wuthering Waves folder layout, so there is no need for `-InstallPath`; running the [quick start](#quick-start) is still useful, because the browser-backdoor checks run whatever game you play.
- Not verified: one PC only; known indicators only.

## What happened

From 2026-09-27, four JavaScript files on Level Infinite's CDN were tampered with. The NIKKE PC launcher loads them on start, and some players got a remote-access trojan (K2F) that steals browser passwords and cookies, the saved NIKKE login, SSH and API keys, crypto wallets, and can run any command. The publisher announced a fix on 2026-11-04, but **a PC that was already infected does not become clean by updating**.

## What you get

| Script | Does | Changes anything? |
|---|---|---|
| `Check-K2F.ps1` | Stage 1 (launcher) and stage 2 (Chrome persistence, other Chromium browsers too) indicators for every user profile on the PC, agent timeline, "live components" vs "history only" | Read-only |
| `Remediate-K2F.ps1` | Stops the launcher, removes the Chrome backdoor, quarantines the launcher cache, blocks domains and IPs | Dry-run by default; `-Apply` acts, moving everything to a quarantine folder (no deletes) |
| `Sweep-Persistence.ps1` | For people who cannot reinstall: autostart points and unsigned files created inside the agent's real active windows | Read-only |
| `Test-CdnFiles.ps1` | Compares the 4 CDN files' ETags with the known-clean ones before you reopen the launcher | HEAD requests only |

## Quick start

1. **Code → Download ZIP**, extract into Downloads.
2. Right-click Start → Terminal, paste:

```powershell
powershell -ExecutionPolicy Bypass -File "$HOME\Downloads\nikke-k2f-check-main\Check-K2F.ps1"
```

3. If infected, **change passwords from your phone first**, then in an elevated terminal dry-run, read, apply:

```powershell
powershell -ExecutionPolicy Bypass -File "$HOME\Downloads\nikke-k2f-check-main\Remediate-K2F.ps1"
```

```powershell
powershell -ExecutionPolicy Bypass -File "$HOME\Downloads\nikke-k2f-check-main\Remediate-K2F.ps1" -Apply
```

Paste this to an AI coding agent:

```text
Read AGENTS.md in this repo. Run Check-K2F.ps1 read-only and explain the verdict to me.
Do not run Remediate-K2F.ps1 with -Apply without asking me first.
```

## Flow

```mermaid
flowchart TD
  A[Check-K2F] -->|no known indicator| G[Test-CdnFiles]
  A -->|infected| P[Rotate passwords and keys from your phone]
  P --> R[Remediate-K2F: dry-run, then -Apply]
  R -->|file locked| RB[Reboot and run again]
  RB --> R
  R --> A2[Check again]
  A2 -->|history only and no reinstall| S[Sweep-Persistence + Defender full scan]
  S --> G
  G -->|all 4 clean, recheck after a few hours| O[Reopen the launcher]
```

## Reading the verdict

| Last line | Meaning |
|---|---|
| 中毒，木馬元件仍在 (infected, live) | The agent ran and its components are still present |
| 曾經中毒，只剩歷史紀錄 (infected, history only) | The agent ran; known components are gone; stolen credentials are still valid |
| 有接觸，未見木馬啟動 (contact) | The launcher loaded the attacker's script; no agent start seen |
| 沒發現已知痕跡 (none known) | No known indicator; not a guarantee |

**What does stage 2 (the browser) take?** It is not a separate browser stealer: it is the same remote-access trojan moved into Chrome, so it starts again every time Chrome opens, even after the game is closed or uninstalled, and can do everything it did inside the launcher. On the browser side it reads saved passwords, cookies (live logins that work without the password or 2FA), the decryption key (Chrome's App-Bound Encryption included) and the data of 28 crypto-wallet extensions. Besides changing passwords, sign out of all devices on each site so the stolen logins stop working. Sources: [docs/FACTS.md](docs/FACTS.md#木馬會偷的東西).

## Differences from the popular one-liner

- leveldb and Code Cache are binary; `Select-String` missed `k2f.agent.state` on a real infected PC. These scripts search bytes (ASCII and UTF-16LE).
- Live components and history are separated, so a cleaned PC does not read "infected" forever.
- Remediation quarantines, never deletes, and never matches processes on an empty path prefix.
- No `irm ... | iex` remote one-liner: remote code loading is exactly what went wrong here.

## You want... read...

| You want | Read |
|---|---|
| Step-by-step check and fix | [Player guide](https://wizerdbache.github.io/nikke-k2f-check/) |
| The source of every indicator | [docs/FACTS.md](docs/FACTS.md) |
| How verdicts are decided, verification, limits | [docs/DEVELOPER.md](docs/DEVELOPER.md) |
| Let an AI agent run it | [AGENTS.md](AGENTS.md) |

## Limits

- Known indicators only; the RAT could run arbitrary commands, so a reinstall remains the safest option.
- **Other games**: claims that Delta Force global / Steam, Honor of Kings global and other Level Infinite titles were hit are **unconfirmed**. The PUBG on that list is PUBG Mobile, which Krafton says has no PC version and is unrelated; PUBG on PC (Steam) is published by Krafton and launched directly by Steam, without the tampered launcher. For the Delta Force Garena edition see [Delta Force players](#delta-force-players-read-this-first); for Wuthering Waves see [Wuthering Waves players](#wuthering-waves-players). For other games pass the launcher folder with `-InstallPath`. See [docs/FACTS.md](docs/FACTS.md#其他遊戲未證實).
- Stage 2 (HKCU, `%LOCALAPPDATA%`) is only reliable from your own PowerShell window; some sandboxed app terminals virtualize those locations.
- Windows Defender may flag the downloaded ZIP (usually a `!ml` machine-learning name such as `Trojan:Script/Wacatac.B!ml`). The code is public for inspection; do not turn off your antivirus for it, report the false positive through Microsoft's file submission page instead. See [docs/FACTS.md](docs/FACTS.md#防毒誤報).
- Not an official tool. Details: [docs/DEVELOPER.md](docs/DEVELOPER.md#限制).

## Credits

[MotherSphere analysis](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) · [WormW sample analysis](https://github.com/WormW/nikke_malware_analysis) · [Bahamut write-up](https://m.gamer.com.tw/forum/C.php?bsn=36390&snA=23304)

## Author

[WizerdBaChe](https://github.com/WizerdBaChe) · [wizerdbache.com](https://wizerdbache.com/) · [YouTube](https://www.youtube.com/@wizerdbache) · [Threads](https://www.threads.com/@wizerd.bache)

## License

[MIT](LICENSE)

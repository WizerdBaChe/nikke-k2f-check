# AGENTS.md

## Facts about this repository

- Purpose: detect and contain the 2026 NIKKE PC launcher supply-chain malware (K2F RAT, C2 `insightjs.com`) on Windows.
- Four PowerShell 5.1 scripts at the repo root. Two are read-only (`Check-K2F.ps1`, `Sweep-Persistence.ps1`), one sends HEAD requests only (`Test-CdnFiles.ps1`), one changes the system (`Remediate-K2F.ps1`, dry-run unless `-Apply`).
- `Remediate-K2F.ps1 -Apply` stops processes, deletes the HKCU COM hijack key in the 64- and 32-bit views, plus any other HKCU CLSID whose in-process server sits in a `PlatformExperienceHelper\<64-hex>` folder or is an unsigned file under a browser `User Data` folder (after exporting each), moves files into `%USERPROFILE%\nikke-k2f-quarantine-<timestamp>`, edits `hosts` and adds or rebuilds a firewall rule (the last two need an elevated shell). It deletes no files.
- `Remediate-K2F.ps1` ends with a numbered summary of every action it would take (dry-run) or took (`-Apply`, with success/fail counts).
- Double-click entry points for non-technical users: `Run-Check.cmd` (in the repo/ZIP) and the one-file `nikke-k2f-check.cmd` on GitHub Releases, built by `tools/Build-OneFile.ps1`. Both run `Run-K2F.ps1`: check first; only on a hit, and only after two typed Y answers (the second after the dry-run summary), elevate and run `Remediate-K2F.ps1 -Apply`. The one-file version embeds the three scripts as base64 with SHA-256, writes them to a new random folder under `%TEMP%`, re-hashes them from disk right before running (exit 92 on mismatch) and downloads nothing. `tests/Run-LauncherTests.ps1` tests both.
- Both `Check-K2F.ps1` and `Remediate-K2F.ps1` cover the current user plus every readable profile under `C:\Users` (launcher cache, browser folders, TEMP); other users' HKCU is not reachable from one account.
- Launcher layouts recognised: NIKKE (`launcher\intl_service`, `%APPDATA%\nikke_launcher*`, including the Google Play Games build at `<drive>:\NIKKE_GOOGLE` with `%APPDATA%\nikke_launcher_google`) and Delta Force Garena (`launcher\service\debug.log`, `%APPDATA%\df_garena_launcher*`); any `%APPDATA%` folder with a `tbs_cache` is also scanned. Other games being affected is unconfirmed (`docs/FACTS.md`, section 其他遊戲); for another game pass its launcher folder with `-InstallPath`. `Remediate-K2F.ps1` quarantines a non-NIKKE cache only when it contains an `insightjs` or `k2f.agent.state` indicator.
- `tests/Run-FixtureTests.ps1` runs fixture tests (one positive and one negative case per check); it creates and then removes five HKCU keys (the known CLSID in the 32-bit view and four random test GUIDs).
- Every indicator and its source is in `docs/FACTS.md`; verdict logic and verification are in `docs/DEVELOPER.md`.
- A `debug.log` with `k2f_chan registered` but no `agent started as` counts as infected (history, exit 2): the line means the agent was downloaded and ran (`docs/FACTS.md`, stage 1). Since 2026-11-05 the official NIKKE client deletes this malware on launch, which also deletes evidence; run the check before the user reopens the launcher.
- `Check-K2F.ps1` exit codes: 3 infected with live components, 2 infected with history only, 1 contact, 4 nothing found but some files could not be read (incomplete, listed in the report's `Unreadable`), 0 nothing known.
- `Remediate-K2F.ps1` deletes a registry key only after its `.reg` export succeeded; a failed export leaves the key in place and is reported as a failure.
- Stage-2 checks read HKCU and `%LOCALAPPDATA%`. If your shell runs inside a packaged (MSIX) app, those views can be virtualized and differ from the user's own shell; then ask the user to run the script in their own PowerShell window and paste the output.
- Reports may contain the computer name, agent id and local paths; `agent_pass` is never printed.

## Steps for an agent helping a user

1. Run `Check-K2F.ps1` (read-only) and explain the verdict in plain language.
2. If infected, tell the user to rotate credentials from another device first; the list is in the player guide (`docs/index.html`) and `docs/FACTS.md`. Credentials of AI tools (API keys, OAuth logins) are in scope: the malware targets them.
3. Run `Remediate-K2F.ps1` without `-Apply`, show the user the plan, and run `-Apply` only after the user says yes.
4. Do not delete anything yourself; do not paste the user's full output publicly (it contains machine names).
5. Before the user reopens the launcher, run `Test-CdnFiles.ps1`.

Developer doc: [docs/DEVELOPER.md](docs/DEVELOPER.md).

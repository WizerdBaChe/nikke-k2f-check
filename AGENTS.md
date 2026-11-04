# AGENTS.md

## Facts about this repository

- Purpose: detect and contain the 2026 NIKKE PC launcher supply-chain malware (K2F RAT, C2 `insightjs.com`) on Windows.
- Four PowerShell 5.1 scripts at the repo root. Two are read-only (`Check-K2F.ps1`, `Sweep-Persistence.ps1`), one sends HEAD requests only (`Test-CdnFiles.ps1`), one changes the system (`Remediate-K2F.ps1`, dry-run unless `-Apply`).
- `Remediate-K2F.ps1 -Apply` stops processes, deletes one HKCU registry key (after exporting it), moves files into `%USERPROFILE%\nikke-k2f-quarantine-<timestamp>`, edits `hosts` and adds a firewall rule (the last two need an elevated shell). It deletes no files.
- Every indicator and its source is in `docs/FACTS.md`; verdict logic and verification are in `docs/DEVELOPER.md`.
- `Check-K2F.ps1` exit codes: 3 infected with live components, 2 infected with history only, 1 contact, 0 nothing known.
- Stage-2 checks read HKCU and `%LOCALAPPDATA%`. If your shell runs inside a packaged (MSIX) app, those views can be virtualized and differ from the user's own shell; then ask the user to run the script in their own PowerShell window and paste the output.
- Reports may contain the computer name, agent id and local paths; `agent_pass` is never printed.

## Steps for an agent helping a user

1. Run `Check-K2F.ps1` (read-only) and explain the verdict in plain language.
2. If infected, tell the user to rotate credentials from another device first; the list is in the player guide (`docs/index.html`) and `docs/FACTS.md`. Credentials of AI tools (API keys, OAuth logins) are in scope: the malware targets them.
3. Run `Remediate-K2F.ps1` without `-Apply`, show the user the plan, and run `-Apply` only after the user says yes.
4. Do not delete anything yourself; do not paste the user's full output publicly (it contains machine names).
5. Before the user reopens the launcher, run `Test-CdnFiles.ps1`.

Developer doc: [docs/DEVELOPER.md](docs/DEVELOPER.md).

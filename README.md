# ClearGuard AV

ClearGuard is a local, layperson-readable Windows security console. It scans real files, tracks quarantine, shows live outbound TCP connections, and explains local security decisions in plain English.

## Customer Download

Public landing page:

```text
https://javen05.github.io/antivirus/
```

Download ZIP:

```text
https://github.com/Javen05/antivirus/archive/refs/heads/main.zip
```

## Run Locally

Install Python 3.11+ on Windows, unzip the project, then run:

```powershell
.\scripts\start-clearguard.ps1
```

Or start it manually:

```powershell
python server.py
```

Then open the local console:

```text
http://127.0.0.1:5288/console.html
```

Run PowerShell as Administrator if you want ClearGuard to create Windows Firewall block rules from the UI.

## Install For Reboot Persistence

To make ClearGuard start again after you power off and sign back into Windows:

```powershell
.\scripts\install-clearguard.ps1
```

This creates a Windows Scheduled Task named `ClearGuard AV Agent` that starts the local agent at user logon. Remove it with:

```powershell
.\scripts\uninstall-clearguard.ps1
```

## Laptop Notifications

When the agent is running, ClearGuard can watch protected folders such as Downloads, Desktop, and Documents. High-risk file changes trigger a Windows pop-up alert and an activity entry in the console.

## Browser Website Warnings

ClearGuard includes an unpacked Chrome/Edge extension in `extension/`.

1. Start the ClearGuard local agent.
2. Open Chrome or Edge extension settings.
3. Enable Developer mode.
4. Choose **Load unpacked**.
5. Select the `extension` folder.

The extension asks `http://127.0.0.1:5288/api/browser-check` to evaluate visited URLs. It can show warning badges, browser notifications, and a local warning interstitial for high-risk domains. It does not upload browsing history to a cloud service.

Limitations in this prototype:

- It is not a kernel driver yet, so it cannot intercept every file before access.
- Website warnings require loading the included `extension/` folder as an unpacked Chrome/Edge extension.
- Firewall block/unblock actions require running the agent from an Administrator PowerShell.

## What Works Now

- Real file and folder scanning.
- Microsoft Defender custom-scan integration for real malware detection using local Defender definitions.
- Microsoft Defender definition updates and quick scans from the ClearGuard console.
- SHA-256 hashing for scanned files.
- Local SHA-256 and domain blocklists.
- EICAR antivirus test string recognition for verifying the scanner path only.
- Script behavior heuristics for encoded PowerShell, remote code download chains, `certutil`, `mshta`, `rundll32`, backup deletion, and Defender-disabling attempts.
- Risk elevation for executable/script-like files in user-writable launch locations.
- Real quarantine with restore/delete metadata.
- Live Windows TCP connection visibility using `Get-NetTCPConnection`.
- Risk labeling for outbound connections from commonly abused Windows tools.
- Optional Windows Firewall outbound block rule creation for a remote IP.
- Safe URL investigation through parsing, DNS resolution, and local red-flag checks.
- Startup persistence audit across Run keys, Startup folders, and scheduled tasks.
- Unpacked Chrome/Edge extension for website warning badges and browser notifications.
- Persistent local settings, rules, activity log, and quarantine index under `.clearguard/`.

## Website vs Local App

The GitHub Pages site is a static product/download page. The antivirus console itself must run on the customer device because browsers cannot scan local files, inspect Windows TCP connections, quarantine files, or create firewall rules from a static website.

## What This Is Not Yet

This is not a signed kernel antivirus driver. An industry endpoint product needs a hardened service, signed drivers, crash-safe enforcement, protected process or anti-tamper strategy, secure updates, telemetry privacy controls, and extensive security review.

The safe progression is:

1. User-mode agent and explainable policy engine.
2. Windows service packaging with least privilege and tamper-resistant storage.
3. Signed file-system minifilter for pre-open/pre-write enforcement.
4. Process, registry, and image-load callbacks.
5. Windows Filtering Platform callouts for traffic enforcement.
6. Cloud reputation and customer-safe threat intelligence.
7. Enterprise management, rollback, audit trails, and compliance controls.

## Defensive Boundary

ClearGuard can inspect, explain, quarantine, restore, delete, and block. It should not exploit sites, bypass access controls, intercept credentials, or provide offensive attack automation. The product moat is making expert-grade defensive telemetry understandable and controllable by normal users.

## Unicorn-Scale Product Moat

- A plain-language policy layer that converts technical events into decisions people understand.
- Local-first trust: useful without uploading private files.
- Guided remediation: every warning has a safe next step.
- Expert mode that grows from the same data model into enterprise EDR.
- Defensive traffic investigation that teaches users what is risky without turning them into attackers.

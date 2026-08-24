# Detection Engineering Lab

A hands-on detection engineering lab that emulates real ATT&CK techniques, captures endpoint telemetry, and validates detections written as code.

## Overview

This project demonstrates the full detection loop end to end: emulate an adversary technique, collect the resulting endpoint telemetry, write detection logic against it, and validate that the detection actually fires on the attack it was built for. Detections are authored in [Sigma](https://github.com/SigmaHQ/sigma) so they stay vendor-neutral and portable across SIEM backends, and every rule is mapped to the MITRE ATT&CK techniques it covers.

Nothing here is written from a blog post or a threat report alone — each rule is developed against telemetry captured from an attack executed in the lab, then tuned against normal system activity to separate signal from noise.

## Architecture

The lab is a single-victim pipeline: a Windows endpoint generates rich process telemetry via Sysmon, a Splunk Universal Forwarder ships it off-host, Splunk Enterprise indexes it as the SIEM, and Sigma rules sit on top as the detection layer.

```
┌──────────────────────────────┐
│  Windows 11 VM (victim)      │
│  ├── Atomic Red Team         │  attack execution
│  └── Sysmon                  │  telemetry generation
│      (SwiftOnSecurity config)│
└──────────────┬───────────────┘
               │  Windows Event Log
               ▼
┌──────────────────────────────┐
│  Splunk Universal Forwarder  │  log shipping
└──────────────┬───────────────┘
               │  TCP 9997
               ▼
┌──────────────────────────────┐
│  Splunk Enterprise (Docker)  │  index / search / hunt
└──────────────┬───────────────┘
               │  SPL hunting → detection logic
               ▼
┌──────────────────────────────┐
│  Sigma rules (detections/)   │  detection-as-code
└──────────────┬───────────────┘
               │
               ▼
        Validation: re-run the atomic, confirm the rule fires
```

**Components**

| Layer | Component |
|---|---|
| Victim endpoint | Windows 11 VM |
| Telemetry | Sysmon, SwiftOnSecurity configuration |
| Log shipping | Splunk Universal Forwarder |
| SIEM | Splunk Enterprise (Docker) |
| Detection layer | Sigma rules, mapped to MITRE ATT&CK |
| Adversary emulation | Atomic Red Team |

## Detection Methodology

Each detection follows the same workflow:

1. **Emulate.** Execute a technique on the victim VM using Atomic Red Team, referenced by its ATT&CK technique ID so the test is reproducible and the coverage claim is specific.
2. **Collect.** Let Sysmon capture the resulting activity and ship it through the forwarder into Splunk.
3. **Analyze.** Hunt the telemetry in SPL to find the fields that actually distinguish the attack — command-line arguments, parent/child process relationships, image paths — rather than the first string that happens to appear.
4. **Refine.** Test the candidate logic against normal system and administrative activity, and tighten it until it separates signal from noise. Anything that survives becomes a documented false positive rather than a silent gap.
5. **Formalize.** Write the logic as a Sigma rule with ATT&CK tags, a severity level, references, and explicit false-positive notes.
6. **Validate.** Re-run the atomic and confirm the rule fires on it — a rule that has never matched its own attack is not a detection.

## Detections

| Rule | Technique(s) | Detects | Log Source | Level | Status |
|---|---|---|---|---|---|
| [powershell_encoded_command.yml](detections/powershell_encoded_command.yml) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — PowerShell<br>[T1027](https://attack.mitre.org/techniques/T1027/) — Obfuscated Files or Information | PowerShell launched with an encoded command argument, covering every abbreviation the CLI accepts (`-e` through `-EncodedCommand`) plus alternate parameter prefixes | Sysmon / `process_creation` | High | Experimental |

## Repo Structure

```
.
├── detections/    Sigma rules — the detection logic, one rule per file
├── attacks/       Atomic Red Team execution notes, mapped to ATT&CK technique IDs
├── telemetry/     Sample captured logs backing each detection
└── docs/          Writeups and screenshots from the detection development process
```

## Skills Demonstrated

- **Detection-as-code** — detections version-controlled, reviewable, and portable rather than clicked into a SIEM console
- **Sigma rule authoring** — field modifiers, regex matching, severity and status metadata, documented false positives
- **MITRE ATT&CK mapping** — technique-level coverage tied to reproducible tests
- **Splunk / SPL** — hunting captured telemetry to derive and validate detection logic
- **Adversary emulation** — Atomic Red Team execution against a live endpoint
- **Telemetry pipeline engineering** — Sysmon → Universal Forwarder → SIEM, including Sysmon configuration and log routing
- **False-positive analysis** — tuning against baseline activity and documenting residual noise for the analyst who inherits the rule

## Disclaimer

This is an isolated lab environment built for defensive security research and education. All attack execution is performed against systems owned by the author.

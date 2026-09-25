# Abyssal Warden documentation

Documents describe the system **as implemented** unless they are marked as a
design for a future component. Design documents say so in their first line.

| Area | Document | Status |
|---|---|---|
| Architecture | [Overview](architecture/overview.md) | current |
| | [Crate boundaries](architecture/crate-boundaries.md) | current |
| | [Detection pipeline](architecture/detection-pipeline.md) | current |
| | [GUI framework evaluation](architecture/gui.md) | proposal |
| | [Architecture decision records](architecture/decisions/README.md) | - |
| Security | [Threat model](security/threat-model.md) | current |
| | [Privilege model](security/privilege-model.md) | current (Linux) |
| | [Quarantine](security/quarantine.md) | current (Linux) |
| | [Content trust: bundles, keyrings, rollback, key procedure](security/content-trust.md) | current |
| | [Update security](security/update-security.md) | signing current; updates design |
| Detection | [Signatures](detection/signatures.md) | current |
| | [YARA rules](detection/yara.md) | current |
| | [Archive scanning](detection/archives.md) | current (ZIP) |
| | [System checks: persistence and integrity rules](detection/system-checks.md) | current (Linux; Windows live) |
| | [Heuristics](detection/heuristics.md) | current (PE rules unmeasured) |
| | [Detection evaluation methodology](detection/testing.md) | current |
| Platform | [Windows](platform/windows.md) | current + research |
| | [Linux](platform/linux.md) | current + research |
| Development | [Setup](development/setup.md) | current |
| | [Testing](development/testing.md) | current |
| | [Release process](development/release-process.md) | current + planned |
| | [Contributing](development/contributing.md) | current |
| User | [Installation](user/installation.md) | current |
| | [Scanning](user/scanning.md) | current |
| | [Remediation](user/remediation.md) | current (Linux) |
| | [System check](user/system-check.md) | current (Linux; Windows live) |
| | [Service](user/service.md) | current (Linux) |
| | [Known limitations](known-limitations.md) | current |

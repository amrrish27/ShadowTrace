# Security policy

## Reporting a vulnerability

Email **security@shadowtrace.invalid** with a description, reproduction steps and the
affected version. Encrypt with our PGP key on request. Do **not** open a public issue.

- Acknowledgement within 3 business days.
- Triage and severity decision within 10 business days.
- Fix window: critical 7 days, high 30 days, medium 90 days, low next release.
- We will credit reporters who want credit, and publish an advisory once a fix ships.

## Scope

In scope: the ShadowTrace API, worker, scanner engine, lab target and deployment files in
this repository. Out of scope: third-party targets you point the scanner at — ShadowTrace
only ever touches targets an operator has explicitly authorized.

## Handling scanned data

Findings can contain sensitive material. Secrets are redacted at capture time
(`app/security/redaction.py`), stored redacted, redacted again on export, and never logged.
If you find a path where a secret survives, treat it as a security bug and report it.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |

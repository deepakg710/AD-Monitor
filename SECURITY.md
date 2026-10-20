# Security Policy

## Scope and Intended Use

**AD Monitor** is an educational, defensive cybersecurity monitoring platform built for controlled Active Directory laboratory environments. It is designed for academic demonstration and laboratory exercises, not for unmonitored production environments.

## Reporting a Vulnerability

If you discover a security vulnerability or sensitive disclosure in this repository:
1. Please do **not** open a public GitHub issue.
2. Report the vulnerability privately by email to the author: `deepak710op@gmail.com`.
3. Include detailed steps to reproduce, affected files/endpoints, and any suggested remediations.

All legitimate disclosures will be reviewed promptly.

## Laboratory Boundaries & Safety

- Only enroll virtual machines and browser profiles under your direct administrative ownership and control.
- Never commit private collector tokens, DPAPI encryption keys, or authentic production Active Directory audit event logs to version control.

## Credential & Authentication Policy

- **No Shared Default Credentials**: AD Monitor does not ship with default administrator credentials. Previously published lab bootstrap passwords are explicitly blocked at both account creation (`create_user`) and sign-in (`login`).
- **Initial Setup**: Administrators must create a unique 12+ character passphrase during initial setup via `python -m backend.cli create-admin --username <username>` or the first-run setup UI.
- **Credential Rotation**: To rotate an administrator password and revoke all active sessions for that user, run:
  ```powershell
  python -m backend.api create-admin --username <username>
  ```

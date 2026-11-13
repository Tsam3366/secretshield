# Security Policy

SecretShield is security-sensitive software. Please do not report suspected vulnerabilities in public issues.

## Reporting a vulnerability

Until a private security contact is configured for this repository, contact the repository owner through GitHub using a private channel. Include:
- A concise description and potential impact.
- Affected version, module, and environment.
- Reproduction steps or a proof of concept that does not expose real credentials.
- Any suggested mitigation.

Please do not include live passwords, API keys, tokens, private keys, or personal data in a report.

## Security design commitments

- Findings and diagnostics must not retain or print original secret values.
- Sanitization must enforce configurable limits on depth, input size, collection size, and total work.
- Object graph traversal must handle cycles safely.
- Regular-expression rules must be reviewed for pathological runtime behavior.
- Reflection must be constrained and must not invoke arbitrary getters by default.
- Protected output paths must fail closed rather than return unsanitized data after an error.
- Integrations must document which output paths they do and do not protect.

These are design requirements, not a claim that every feature is already implemented in the current development version.

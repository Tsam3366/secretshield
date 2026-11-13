# Contributing

Thank you for considering a contribution to SecretShield.

## Before you start

- Open an issue to discuss substantial changes.
- Do not submit real credentials, tokens, private keys, or personal data in tests or examples.
- Keep the framework-independent API free of optional framework dependencies.
- Add tests for behavior and security edge cases.

## Development environment

- JDK 25
- Maven 3.9+

Run the complete verification build:

```bash
mvn clean verify
```

## Pull requests

- Use a focused change with a clear description.
- Include tests and update documentation where relevant.
- Explain security implications and failure behavior.
- Keep public API changes deliberate and document compatibility impact.

## Commit message convention

Use Conventional Commit-style messages, for example:

- `feat(core): add API token detection rule`
- `fix(core): stop cyclic object traversal`
- `docs: clarify masking policy`
- `test(core): cover nested map sanitization`

## Security

For vulnerability reports, follow [SECURITY.md](SECURITY.md). Do not disclose vulnerabilities in public issues.

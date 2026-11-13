# SecretShield

**SecretShield** is an open-source Java library for detecting, classifying, and protecting sensitive information in application data.

The project is being developed with a framework-independent core and optional integrations for Jackson, Spring Boot, and logging frameworks.

> **Development status:** Initial project foundation. APIs and behavior are subject to change until the first stable release.

## Goals

- Detect credentials, tokens, private keys, and selected personally identifiable information.
- Classify findings without retaining the original secret values.
- Apply explicit masking, partial masking, or redaction policies.
- Sanitize nested Java objects and collections with bounded traversal.
- Provide optional integrations without coupling the core to a framework.
- Fail safely: protected output paths must never silently fall back to raw sensitive values.

## Planned modules

| Module | Responsibility |
| --- | --- |
| `secretshield-api` | Public interfaces and immutable domain models |
| `secretshield-core` | Detection, policy evaluation, masking, and object traversal |
| `secretshield-json-jackson` | Jackson tree and JSON integration |
| `secretshield-spring-boot-autoconfigure` | Spring Boot configuration and bean setup |
| `secretshield-spring-boot-starter` | Convenience starter |
| `secretshield-logback` | Logback integration |
| `secretshield-log4j2` | Log4j2 integration |
| `secretshield-testkit` | Reusable security test fixtures |

Only the API and core modules are included in the initial build. Integrations will be added incrementally.

## Requirements

- JDK 25
- Maven 3.9+

## Build

```bash
./mvnw clean verify
```

On Windows:

```powershell
mvnw.cmd clean verify
```

## Security principles

- Never include original secret values in findings, exceptions, logs, or metrics.
- Bound input size, nesting depth, collection size, and traversal work.
- Detect cyclic object graphs.
- Avoid unsafe reflection and unbounded regular-expression execution.
- Do not mutate caller-owned objects unless an API explicitly documents that behavior.
- Do not claim that logging integrations protect paths they do not intercept.

See [SECURITY.md](SECURITY.md) for reporting guidance and the security design principles.

## Project roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

SecretShield is licensed under the [Apache License 2.0](LICENSE).

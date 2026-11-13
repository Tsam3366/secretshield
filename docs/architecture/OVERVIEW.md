# Architecture Overview

## Design

SecretShield uses a framework-independent core with optional adapters.

```text
Application
   |
   +-- Optional integrations (Jackson / Spring Boot / Logback / Log4j2)
   |
   +-- secretshield-core
   |      Detection -> Classification -> Policy -> Masking/Sanitization
   |
   +-- secretshield-api
          Public contracts and immutable metadata models
```

## Trust boundaries

- Application input is untrusted and may be malformed, deeply nested, cyclic, or very large.
- Detection output is metadata only; raw matched values must not escape into findings.
- Sanitization output is safe only for the paths and data types explicitly supported by the selected integration.
- Logging adapters cannot protect data emitted through unrelated appenders, direct console writes, external agents, or paths they do not intercept.

## Fail-closed behavior

If a protected operation cannot complete within configured limits or encounters an unsupported unsafe object, it must report a safe failure. It must not silently return the original unsanitized representation.

## Compatibility

The initial baseline is Java 25. Optional integration modules must not add their dependencies to the framework-independent API module.

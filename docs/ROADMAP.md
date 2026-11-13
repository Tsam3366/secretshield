# SecretShield Roadmap

This roadmap is directional. Milestones are complete only when implementation, tests, and documentation are merged.

## Phase 1 — Foundation
- [x] Create public repository and project conventions.
- [x] Establish Java 25 Maven parent and initial modules.
- [ ] Add Maven Wrapper and CI verification.
- [ ] Finalize public API contracts.

## Phase 2 — Framework-independent core
- [x] Initial detection rule contracts and rule execution (registry extensibility is provided by immutable rule lists; configurable registry remains future work).
- [ ] Built-in detectors for credentials, tokens, and selected PII.
- [ ] Immutable findings that never retain raw secret values.
- [ ] Masking and redaction strategies.
- [ ] Bounded object graph traversal and cycle detection.
- [ ] Safe sanitization for maps, collections, arrays, and nested objects.

## Phase 3 — Integrations
- [ ] Jackson JSON-tree integration.
- [ ] Spring Boot auto-configuration and starter.
- [ ] Logback integration.
- [ ] Log4j2 integration.

## Phase 4 — Hardening and release
- [ ] Security-focused regression suite.
- [ ] Performance benchmarks and resource-limit validation.
- [ ] Compatibility and dependency review.
- [ ] Documentation and examples.
- [ ] Release candidate, signing, and Maven Central publication.

## Release principle

Do not label a release production-ready until supported paths have documented behavior, security tests, and explicit limitations.

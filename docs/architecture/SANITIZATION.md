# Bounded object sanitization

`DefaultSensitiveDataSanitizer` creates a detached normalized graph and applies the configured detector plus the built-in exact field-name rule.

## Normalized output

- Maps become `LinkedHashMap` instances.
- Collections and arrays become lists.
- Application objects become maps of readable instance field names to sanitized values.
- `Optional` values become their contained sanitized value, or `null` when empty.
- Enums become their constant names.
- Supported immutable scalar values are preserved.
- Non-empty `byte[]`, `Byte[]`, `char[]`, and `Character[]` values are masked as opaque data.

The source graph is never mutated. Identity tracking preserves cycles and shared references in the detached output. The returned maps and lists are mutable because preserving cycles requires mutable containers.

## Detection and masking

String values are evaluated by the supplied `SecretDetector`, with the built-in exact field-name rule applied first. Non-string values under recognized sensitive field names are masked as opaque values. Private-key findings are redacted; email and phone findings use partial masking; other categories use full masking. Opaque values use full masking unless the field is classified as a private key.

Map string keys are inspected for recognizable secret patterns. Their original string is used only as the value's field-name hint; logical paths use numeric key/value positions rather than copying map keys into diagnostics. Only null, string, enum, and supported immutable scalar map keys are accepted. A collision caused by masking two keys fails the operation.

## Resource and failure behavior

Default traversal limits are depth 32 and 10,000 visited values. Map keys count toward the node limit. Candidate strings longer than 65,536 UTF-16 code units fail closed rather than bypassing detection.

Unsupported platform objects, inaccessible application fields, complex map keys, detector/masking failures, and exceeded limits cause a generic `SecretShieldException`. The exception has no cause and contains no source value. No partial output or original-object fallback is returned.

## Important limitations

This is a conservative first core implementation, not a universal serializer or a guarantee that every possible secret is recognized. Detection coverage depends on the supplied rules and their limitations. Unknown secret formats in otherwise supported strings can remain unchanged. Custom collection implementations are traversed through their elements; implementation-specific extra fields are not copied. Applications should use explicit rules for their own secret formats and treat any sanitization exception as a failed operation.

# Detection API

The first detection API evaluates one candidate value at a time.

## Data flow

1. The caller creates a `DetectionInput` with an optional field name, a logical `DataLocation`, and the candidate value.
2. A `SecretDetector` evaluates its configured `DetectionRule` instances.
3. Rules return optional `SecretFinding` metadata.
4. `DetectionResult` exposes an immutable list of findings.

## Sensitive-value handling

`DetectionInput` necessarily carries the candidate value during evaluation. Treat it as sensitive: do not log it, retain it, or include it in exception messages. Its diagnostic string representation redacts the candidate value.

A `SecretFinding` contains category, logical location, rule identifier, and confidence only. It must never contain the matched value.

## Initial built-in rule

`FieldNameDetectionRule` uses an exact, case-insensitive allow-list for common credential field names. It deliberately does not classify generic names such as `key` or `id`, or use substring matching. This limits false positives but means differently named credentials require additional rules.

This rule is a metadata heuristic, not proof that the field value is a valid credential. Pattern-based value inspection will be added separately.

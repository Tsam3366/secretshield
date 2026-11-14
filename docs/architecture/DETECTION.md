# Detection API

The detection API evaluates one candidate value at a time.

## Data flow

1. The caller creates a `DetectionInput` with an optional field name, a logical `DataLocation`, and the candidate value.
2. A `SecretDetector` evaluates its configured `DetectionRule` instances.
3. Rules return optional `SecretFinding` metadata.
4. `DetectionResult` exposes an immutable list of findings.

## Sensitive-value handling

`DetectionInput` necessarily carries the candidate value during evaluation. Treat it as sensitive: do not log it, retain it, or include it in exception messages. Its diagnostic string representation redacts the candidate value.

A `SecretFinding` contains category, logical location, rule identifier, and confidence only. It must never contain the matched value.

## Built-in rules

- `FieldNameDetectionRule` uses an exact, case-insensitive allow-list for common credential field names. Generic names such as `key` and `id` and substring matches are intentionally excluded.
- `JwtDetectionRule` recognizes a bounded compact signed-JWT shape, requiring base64url segments and object-shaped decoded header and payload. It does not verify signatures, parse all JSON semantics, or validate claims.
- `BearerTokenDetectionRule` recognizes opaque bearer credentials in an Authorization header value using the RFC 6750 token character set and a minimum length to reduce false positives.
- `PemPrivateKeyDetectionRule` recognizes complete PEM blocks for common private-key types. A header without its matching footer is not enough.
- `EmailAddressDetectionRule` finds common ASCII email forms with bounded local-part and domain lengths using a linear scanner rather than a backtracking regular expression. It is not a full RFC 5322 or internationalized-email parser.

These rules provide conservative indicators, not proof of validity or ownership. Detection confidence is a heuristic and must not be treated as an authentication or authorization decision. Pattern rules inspect candidate values transiently and return metadata only. No rule stores or returns the matched value.

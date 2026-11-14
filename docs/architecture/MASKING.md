# Masking and redaction

The framework-independent API exposes `MaskingStrategy`, and the core module provides three built-in transformations selected through `MaskingType`.

- **Full mask** replaces every non-empty input with the fixed marker `[MASKED]`. The marker does not reveal the original value length.
- **Partial mask** preserves configured leading and trailing Unicode code points and replaces the middle with `***`. By default it preserves one code point at each edge. Values too short to safely preserve both edges are fully masked.
- **Redaction** replaces every non-empty input with `[REDACTED]`.

Empty input remains empty because it contains no characters to disclose. Null input is rejected with a fixed, value-free exception message.

The built-in strategies are stateless and do not retain the input. Partial masking necessarily discloses the configured edge characters; callers must choose edge counts appropriate to the data category. Masking is a presentation transformation, not encryption or secure deletion of the original value.

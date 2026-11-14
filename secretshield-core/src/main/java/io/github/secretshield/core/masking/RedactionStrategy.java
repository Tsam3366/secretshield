package io.github.secretshield.core.masking;

import io.github.secretshield.api.masking.MaskingStrategy;
import java.util.Objects;

/** Replaces a non-empty value with an explicit redaction marker. */
public final class RedactionStrategy implements MaskingStrategy {
    public static final String REDACTED_MARKER = "[REDACTED]";

    @Override
    public String mask(String value) {
        Objects.requireNonNull(value, "value must not be null");
        return value.isEmpty() ? "" : REDACTED_MARKER;
    }
}

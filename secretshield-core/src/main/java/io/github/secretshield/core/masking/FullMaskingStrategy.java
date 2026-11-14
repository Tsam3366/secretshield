package io.github.secretshield.core.masking;

import io.github.secretshield.api.masking.MaskingStrategy;
import java.util.Objects;

/** Replaces a non-empty value with a fixed marker that does not reveal its length. */
public final class FullMaskingStrategy implements MaskingStrategy {
    public static final String MASKED_MARKER = "[MASKED]";

    @Override
    public String mask(String value) {
        Objects.requireNonNull(value, "value must not be null");
        return value.isEmpty() ? "" : MASKED_MARKER;
    }
}

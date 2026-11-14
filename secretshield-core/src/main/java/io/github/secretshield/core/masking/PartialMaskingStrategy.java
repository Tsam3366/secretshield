package io.github.secretshield.core.masking;

import io.github.secretshield.api.masking.MaskingStrategy;
import java.util.Objects;

/**
 * Preserves configured edge code points and replaces the middle with a fixed marker.
 *
 * <p>Values too short to preserve both edges are fully masked. Code-point-aware
 * slicing avoids splitting UTF-16 surrogate pairs.</p>
 */
public final class PartialMaskingStrategy implements MaskingStrategy {
    private static final String MIDDLE_MARKER = "***";

    private final int visiblePrefixCodePoints;
    private final int visibleSuffixCodePoints;
    private final FullMaskingStrategy fullMaskingStrategy = new FullMaskingStrategy();

    public PartialMaskingStrategy() {
        this(1, 1);
    }

    public PartialMaskingStrategy(int visiblePrefixCodePoints, int visibleSuffixCodePoints) {
        if (visiblePrefixCodePoints < 0 || visibleSuffixCodePoints < 0) {
            throw new IllegalArgumentException("visible code-point counts must not be negative");
        }
        this.visiblePrefixCodePoints = visiblePrefixCodePoints;
        this.visibleSuffixCodePoints = visibleSuffixCodePoints;
    }

    @Override
    public String mask(String value) {
        Objects.requireNonNull(value, "value must not be null");
        if (value.isEmpty()) {
            return "";
        }

        int codePointCount = value.codePointCount(0, value.length());
        long visibleCount = (long) visiblePrefixCodePoints + visibleSuffixCodePoints;
        if (codePointCount <= visibleCount) {
            return fullMaskingStrategy.mask(value);
        }

        int prefixEnd = value.offsetByCodePoints(0, visiblePrefixCodePoints);
        int suffixStart = value.offsetByCodePoints(value.length(), -visibleSuffixCodePoints);
        return value.substring(0, prefixEnd) + MIDDLE_MARKER + value.substring(suffixStart);
    }
}

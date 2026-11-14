package io.github.secretshield.core.masking;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FullMaskingStrategyTest {
    private final FullMaskingStrategy strategy = new FullMaskingStrategy();

    @Test
    void replacesValueWithFixedLengthIndependentMarker() {
        String secret = "highly-sensitive-password";
        String masked = strategy.mask(secret);

        assertEquals(FullMaskingStrategy.MASKED_MARKER, masked);
        assertFalse(masked.contains(secret));
    }

    @Test
    void preservesEmptyInputAsEmpty() {
        assertEquals("", strategy.mask(""));
    }

    @Test
    void rejectsNullInput() {
        assertThrows(NullPointerException.class, () -> strategy.mask(null));
    }
}

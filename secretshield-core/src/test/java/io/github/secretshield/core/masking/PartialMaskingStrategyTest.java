package io.github.secretshield.core.masking;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PartialMaskingStrategyTest {
    @Test
    void preservesOnlyConfiguredEdges() {
        assertEquals("a***z", new PartialMaskingStrategy().mask("alice@example.com"));
        assertEquals("ab***yz", new PartialMaskingStrategy(2, 2).mask("abcdefyz"));
    }

    @Test
    void fullyMasksValuesTooShortToPreserveBothEdges() {
        assertEquals(FullMaskingStrategy.MASKED_MARKER,
                new PartialMaskingStrategy(1, 1).mask("ab"));
    }

    @Test
    void handlesSupplementaryUnicodeCodePointsWithoutSplittingSurrogates() {
        String value = "A😀middle😎Z";
        assertEquals("A***Z", new PartialMaskingStrategy(1, 1).mask(value));
    }

    @Test
    void rejectsNegativeVisibleCounts() {
        assertThrows(IllegalArgumentException.class, () -> new PartialMaskingStrategy(-1, 1));
        assertThrows(IllegalArgumentException.class, () -> new PartialMaskingStrategy(1, -1));
    }
}

package io.github.secretshield.core.traversal;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TraversalLimitsTest {

    @Test
    void rejectsNegativeDepth() {
        assertThrows(IllegalArgumentException.class, () -> new TraversalLimits(-1, 10));
    }

    @Test
    void rejectsZeroNodeLimit() {
        assertThrows(IllegalArgumentException.class, () -> new TraversalLimits(1, 0));
    }

    @Test
    void providesConservativeDefaults() {
        assertEquals(new TraversalLimits(32, 10_000), TraversalLimits.defaults());
    }
}

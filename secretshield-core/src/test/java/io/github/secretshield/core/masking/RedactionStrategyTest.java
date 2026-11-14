package io.github.secretshield.core.masking;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RedactionStrategyTest {
    @Test
    void emitsExplicitRedactionMarker() {
        String secret = "private-key-material";
        String redacted = new RedactionStrategy().mask(secret);

        assertEquals(RedactionStrategy.REDACTED_MARKER, redacted);
        assertFalse(redacted.contains(secret));
    }
}

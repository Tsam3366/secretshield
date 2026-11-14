package io.github.secretshield.core.masking;

import io.github.secretshield.api.masking.MaskingType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DefaultMaskingEngineTest {
    private final DefaultMaskingEngine engine = new DefaultMaskingEngine();

    @Test
    void dispatchesEveryBuiltInMaskingType() {
        assertEquals("[MASKED]", engine.mask("secret", MaskingType.FULL_MASK));
        assertEquals("s***t", engine.mask("secret", MaskingType.PARTIAL_MASK));
        assertEquals("[REDACTED]", engine.mask("secret", MaskingType.REDACT));
    }

    @Test
    void rejectsNullArguments() {
        assertThrows(NullPointerException.class, () -> engine.mask(null, MaskingType.FULL_MASK));
        assertThrows(NullPointerException.class, () -> engine.mask("secret", null));
    }
}

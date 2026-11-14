package io.github.secretshield.core.masking;

import io.github.secretshield.api.masking.MaskingType;
import io.github.secretshield.api.masking.MaskingStrategy;
import java.util.Map;
import java.util.Objects;

/** Stateless dispatcher for SecretShield's built-in masking operations. */
public final class DefaultMaskingEngine {
    private final Map<MaskingType, MaskingStrategy> strategies;

    public DefaultMaskingEngine() {
        this(new FullMaskingStrategy(), new PartialMaskingStrategy(), new RedactionStrategy());
    }

    public DefaultMaskingEngine(
            MaskingStrategy fullMask,
            MaskingStrategy partialMask,
            MaskingStrategy redaction) {
        this.strategies = Map.of(
                MaskingType.FULL_MASK, Objects.requireNonNull(fullMask, "fullMask must not be null"),
                MaskingType.PARTIAL_MASK, Objects.requireNonNull(partialMask, "partialMask must not be null"),
                MaskingType.REDACT, Objects.requireNonNull(redaction, "redaction must not be null"));
    }

    /**
     * Applies the selected strategy.
     *
     * @param value sensitive value
     * @param maskingType protection operation
     * @return protected value
     */
    public String mask(String value, MaskingType maskingType) {
        Objects.requireNonNull(value, "value must not be null");
        Objects.requireNonNull(maskingType, "maskingType must not be null");
        return strategies.get(maskingType).mask(value);
    }
}

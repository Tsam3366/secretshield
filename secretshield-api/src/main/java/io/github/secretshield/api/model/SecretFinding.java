package io.github.secretshield.api.model;

import java.util.Objects;

/**
 * A detection result that deliberately contains metadata only.
 *
 * <p>The original sensitive value must never be stored in this type.</p>
 *
 * @param category detected category
 * @param location logical location of the detection
 * @param ruleId stable identifier of the rule that matched
 * @param confidence confidence in the classification, from 0.0 to 1.0
 */
public record SecretFinding(
        SecretCategory category,
        DataLocation location,
        String ruleId,
        double confidence) {

    public SecretFinding {
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(location, "location must not be null");
        Objects.requireNonNull(ruleId, "ruleId must not be null");
        if (ruleId.isBlank()) {
            throw new IllegalArgumentException("ruleId must not be blank");
        }
        if (!Double.isFinite(confidence) || confidence < 0.0 || confidence > 1.0) {
            throw new IllegalArgumentException("confidence must be between 0.0 and 1.0");
        }
    }

    @Override
    public String toString() {
        return "SecretFinding[category=" + category
                + ", location=" + location
                + ", ruleId=" + ruleId
                + ", confidence=" + confidence + "]";
    }
}

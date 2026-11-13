package io.github.secretshield.api.detector;

import io.github.secretshield.api.model.DataLocation;
import java.util.Objects;

/**
 * Input supplied to detection rules.
 *
 * <p>This object temporarily carries the candidate value for inspection.
 * Implementations must not log it, retain it beyond the detection operation,
 * or include it in diagnostics.</p>
 */
public final class DetectionInput {
    private final String fieldName;
    private final DataLocation location;
    private final String value;

    public DetectionInput(String fieldName, DataLocation location, String value) {
        this.fieldName = fieldName;
        this.location = Objects.requireNonNull(location, "location must not be null");
        this.value = Objects.requireNonNull(value, "value must not be null");
    }

    public String fieldName() {
        return fieldName;
    }

    public DataLocation location() {
        return location;
    }

    /**
     * Returns the candidate value for rule evaluation.
     *
     * <p>Callers and rules must treat the returned value as sensitive.</p>
     */
    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return "DetectionInput[fieldName=" + fieldName
                + ", location=" + location
                + ", value=[REDACTED]]";
    }
}

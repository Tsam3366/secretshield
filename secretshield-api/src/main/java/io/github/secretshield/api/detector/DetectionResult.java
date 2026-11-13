package io.github.secretshield.api.detector;

import io.github.secretshield.api.model.SecretFinding;
import java.util.List;

/** Immutable collection of metadata-only findings for one input. */
public record DetectionResult(List<SecretFinding> findings) {

    public DetectionResult {
        findings = List.copyOf(findings);
    }

    public boolean hasFindings() {
        return !findings.isEmpty();
    }

    public static DetectionResult empty() {
        return new DetectionResult(List.of());
    }
}

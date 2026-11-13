package io.github.secretshield.core.detector;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionResult;
import io.github.secretshield.api.detector.DetectionRule;
import io.github.secretshield.api.detector.SecretDetector;
import io.github.secretshield.api.model.SecretFinding;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Runs a fixed, immutable set of detection rules against one input.
 *
 * <p>Rule instances should be stateless or otherwise safe for concurrent use.</p>
 */
public final class DefaultSecretDetector implements SecretDetector {
    private final List<DetectionRule> rules;

    public DefaultSecretDetector(List<? extends DetectionRule> rules) {
        Objects.requireNonNull(rules, "rules must not be null");
        this.rules = List.copyOf(rules);
        if (this.rules.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("rules must not contain null entries");
        }
    }

    @Override
    public DetectionResult detect(DetectionInput input) {
        Objects.requireNonNull(input, "input must not be null");
        List<SecretFinding> findings = new ArrayList<>();
        for (DetectionRule rule : rules) {
            rule.detect(input).ifPresent(findings::add);
        }
        return new DetectionResult(findings);
    }
}

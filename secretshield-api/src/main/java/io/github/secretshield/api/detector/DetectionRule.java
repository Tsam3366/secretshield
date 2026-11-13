package io.github.secretshield.api.detector;

import io.github.secretshield.api.model.SecretFinding;
import java.util.Optional;

/**
 * A single, independently identifiable secret detection rule.
 *
 * <p>Rules must return metadata only. They must never put the matched value
 * into a finding, exception message, or diagnostic string.</p>
 */
@FunctionalInterface
public interface DetectionRule {

    /**
     * Evaluates one candidate input.
     *
     * @param input sensitive candidate input
     * @return a finding when this rule matches, otherwise empty
     */
    Optional<SecretFinding> detect(DetectionInput input);
}

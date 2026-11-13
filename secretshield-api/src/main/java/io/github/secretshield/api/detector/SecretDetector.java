package io.github.secretshield.api.detector;

/** Detects sensitive information in a single candidate input. */
@FunctionalInterface
public interface SecretDetector {

    /**
     * Detects sensitive information without returning the original value.
     *
     * @param input candidate input
     * @return immutable detection result
     */
    DetectionResult detect(DetectionInput input);
}

package io.github.secretshield.api.sanitizer;

/**
 * Result of a completed sanitization operation.
 *
 * <p>The returned graph is a detached normalized copy. Its maps and lists
 * remain mutable so that graph cycles and shared references can be preserved.
 * This result retains no reference to the original input graph.</p>
 *
 * @param value sanitized graph
 * @param visitedNodes number of values inspected
 * @param maskedValues number of values replaced by a protection marker
 * @param cyclesDetected number of back-references to active objects
 */
public record SanitizationResult(
        Object value,
        int visitedNodes,
        int maskedValues,
        int cyclesDetected) {

    public SanitizationResult {
        if (visitedNodes < 0 || maskedValues < 0 || cyclesDetected < 0) {
            throw new IllegalArgumentException("Sanitization counters must not be negative");
        }
    }

    /**
     * Deliberately excludes the sanitized graph from diagnostic output.
     */
    @Override
    public String toString() {
        return "SanitizationResult[visitedNodes=" + visitedNodes
                + ", maskedValues=" + maskedValues
                + ", cyclesDetected=" + cyclesDetected
                + ", value=[SANITIZED_GRAPH]]";
    }
}

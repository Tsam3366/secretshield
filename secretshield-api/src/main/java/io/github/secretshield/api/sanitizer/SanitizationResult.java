package io.github.secretshield.api.sanitizer;

/**
 * Result of a completed sanitization operation.
 *
 * <p>The returned graph is a detached normalized copy. Its maps and lists
 * remain mutable so that graph cycles and shared references can be preserved.
 * This result retains no reference to the original input graph.</p>
 */
public final class SanitizationResult {
    private final Object value;
    private final int visitedNodes;
    private final int maskedValues;
    private final int cyclesDetected;

    public SanitizationResult(Object value, int visitedNodes, int maskedValues, int cyclesDetected) {
        if (visitedNodes < 0 || maskedValues < 0 || cyclesDetected < 0) {
            throw new IllegalArgumentException("Sanitization counters must not be negative");
        }
        this.value = value;
        this.visitedNodes = visitedNodes;
        this.maskedValues = maskedValues;
        this.cyclesDetected = cyclesDetected;
    }

    public Object value() {
        return value;
    }

    public int visitedNodes() {
        return visitedNodes;
    }

    public int maskedValues() {
        return maskedValues;
    }

    public int cyclesDetected() {
        return cyclesDetected;
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

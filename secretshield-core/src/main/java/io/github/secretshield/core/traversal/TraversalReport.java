package io.github.secretshield.core.traversal;

/**
 * Metadata about one traversal. No visited object or source value is retained.
 *
 * @param visitedNodes number of values delivered to the visitor
 * @param cyclesDetected number of references to objects on the active path
 * @param inaccessibleFields number of object fields that could not be read
 * @param truncated whether configured limits prevented complete traversal
 */
public record TraversalReport(
        int visitedNodes,
        int cyclesDetected,
        int inaccessibleFields,
        boolean truncated) {

    public TraversalReport {
        if (visitedNodes < 0 || cyclesDetected < 0 || inaccessibleFields < 0) {
            throw new IllegalArgumentException("Traversal counters must not be negative");
        }
    }

    public boolean isComplete() {
        return !truncated && inaccessibleFields == 0;
    }

    public static TraversalReport empty() {
        return new TraversalReport(0, 0, 0, false);
    }
}

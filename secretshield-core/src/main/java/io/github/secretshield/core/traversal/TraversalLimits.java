package io.github.secretshield.core.traversal;

/**
 * Resource limits for object graph traversal.
 *
 * @param maxDepth maximum depth from the root; the root is depth zero
 * @param maxNodes maximum number of visited values, including the root
 */
public record TraversalLimits(int maxDepth, int maxNodes) {

    private static final int DEFAULT_MAX_DEPTH = 32;
    private static final int DEFAULT_MAX_NODES = 10_000;

    public TraversalLimits {
        if (maxDepth < 0) {
            throw new IllegalArgumentException("maxDepth must not be negative");
        }
        if (maxNodes < 1) {
            throw new IllegalArgumentException("maxNodes must be at least one");
        }
    }

    /** Conservative defaults suitable for ordinary application payloads. */
    public static TraversalLimits defaults() {
        return new TraversalLimits(DEFAULT_MAX_DEPTH, DEFAULT_MAX_NODES);
    }
}

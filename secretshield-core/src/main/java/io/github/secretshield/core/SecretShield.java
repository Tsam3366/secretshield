package io.github.secretshield.core;

/**
 * Entry point for the framework-independent SecretShield engine.
 *
 * <p>The detection and sanitization APIs will be added in subsequent
 * milestones. This class intentionally exposes no incomplete protection
 * behavior.</p>
 */
public final class SecretShield {

    public static final String VERSION = "0.1.0-SNAPSHOT";

    private SecretShield() {
        throw new AssertionError("No instances");
    }
}

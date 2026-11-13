package io.github.secretshield.api.exception;

/**
 * Base exception for SecretShield failures.
 *
 * <p>Messages must describe the operation and failure category only. Never
 * include source values, serialized objects, credentials, or tokens.</p>
 */
public class SecretShieldException extends RuntimeException {
    public SecretShieldException(String message) {
        super(message);
    }

    public SecretShieldException(String message, Throwable cause) {
        super(message, cause);
    }
}

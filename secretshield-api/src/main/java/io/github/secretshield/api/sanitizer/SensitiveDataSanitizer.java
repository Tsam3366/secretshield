package io.github.secretshield.api.sanitizer;

/**
 * Produces a detached, protected representation of an input object graph.
 *
 * <p>Implementations must not mutate the input or return it as a fallback
 * when sanitization is incomplete.</p>
 */
@FunctionalInterface
public interface SensitiveDataSanitizer {

    /**
     * Sanitizes the supplied object graph.
     *
     * @param input source object graph; may be {@code null}
     * @return completed sanitized representation and value-free statistics
     * @throws io.github.secretshield.api.exception.SecretShieldException
     *         if the graph cannot be completely and safely sanitized
     */
    SanitizationResult sanitize(Object input);
}

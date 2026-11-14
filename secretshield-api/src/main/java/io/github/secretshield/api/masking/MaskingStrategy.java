package io.github.secretshield.api.masking;

/**
 * Transforms a sensitive value into a protected representation.
 *
 * <p>Implementations must not retain the supplied value or expose it through
 * logs, diagnostics, exceptions, or other side channels.</p>
 */
@FunctionalInterface
public interface MaskingStrategy {

    /**
     * Returns a protected representation of the supplied value.
     *
     * @param value sensitive value to transform
     * @return protected representation; never the original non-empty value
     */
    String mask(String value);
}

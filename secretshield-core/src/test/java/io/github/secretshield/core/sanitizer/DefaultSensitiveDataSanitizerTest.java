package io.github.secretshield.core.sanitizer;

import io.github.secretshield.api.detector.DetectionRule;
import io.github.secretshield.api.exception.SecretShieldException;
import io.github.secretshield.api.sanitizer.SanitizationResult;
import io.github.secretshield.core.detector.DefaultSecretDetector;
import io.github.secretshield.core.detector.rules.BearerTokenDetectionRule;
import io.github.secretshield.core.detector.rules.EmailAddressDetectionRule;
import io.github.secretshield.core.detector.rules.FieldNameDetectionRule;
import io.github.secretshield.core.detector.rules.JwtDetectionRule;
import io.github.secretshield.core.detector.rules.PemPrivateKeyDetectionRule;
import io.github.secretshield.core.traversal.TraversalLimits;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DefaultSensitiveDataSanitizerTest {
    private static final String PASSWORD = "original-password-must-not-escape";
    private final DefaultSensitiveDataSanitizer sanitizer = new DefaultSensitiveDataSanitizer(
            new DefaultSecretDetector(List.<DetectionRule>of(
                    new FieldNameDetectionRule(),
                    new JwtDetectionRule(),
                    new BearerTokenDetectionRule(),
                    new PemPrivateKeyDetectionRule(),
                    new EmailAddressDetectionRule())));

    @Test
    void sanitizesMapValuesNestedObjectsCollectionsAndArraysWithoutMutatingInput() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("password", PASSWORD);
        input.put("contact", "alex@example.com");
        input.put("notes", new ArrayList<>(List.of("ordinary text", "Bearer abcdefghijklmnopqrstuvwxyz")));
        input.put("numbers", new int[]{3, 5, 8});

        SanitizationResult result = sanitizer.sanitize(input);

        Map<?, ?> output = (Map<?, ?>) result.value();
        assertEquals("[MASKED]", output.get("password"));
        assertEquals("a***m", output.get("contact"));
        List<?> notes = (List<?>) output.get("notes");
        assertEquals("ordinary text", notes.get(0));
        assertEquals("[MASKED]", notes.get(1));
        assertEquals(List.of(3, 5, 8), output.get("numbers"));
        assertEquals(PASSWORD, input.get("password"));
        assertEquals(3, result.maskedValues());
        assertFalse(result.toString().contains(PASSWORD));
    }

    @Test
    void masksSensitiveNonStringFieldsAndOpaqueCharacterArrays() {
        Credentials input = new Credentials();

        Map<?, ?> output = (Map<?, ?>) sanitizer.sanitize(input).value();

        assertEquals("[MASKED]", output.get("password"));
        assertEquals("[REDACTED]", output.get("privateKey"));
        assertEquals("[MASKED]", output.get("characterSecret"));
    }

    @Test
    void preservesCyclesAndSharedReferencesInDetachedGraph() {
        Map<String, Object> cycle = new LinkedHashMap<>();
        cycle.put("self", cycle);
        SharedPayload shared = new SharedPayload();
        List<Object> input = new ArrayList<>(Arrays.asList(cycle, shared, shared));

        SanitizationResult result = sanitizer.sanitize(input);
        List<?> output = (List<?>) result.value();
        Map<?, ?> sanitizedCycle = (Map<?, ?>) output.get(0);

        assertSame(sanitizedCycle, sanitizedCycle.get("self"));
        assertSame(output.get(1), output.get(2));
        assertEquals(1, result.cyclesDetected());
        assertNotSame(input, output);
        assertEquals("visible", ((Map<?, ?>) output.get(1)).get("label"));
    }

    @Test
    void masksSecretLookingMapKeysAndRejectsMaskingCollisions() {
        Map<String, Object> oneKey = new LinkedHashMap<>();
        oneKey.put("Bearer abcdefghijklmnopqrstuvwxyz", "safe");

        Map<?, ?> sanitized = (Map<?, ?>) sanitizer.sanitize(oneKey).value();
        assertTrue(sanitized.containsKey("[MASKED]"));

        Map<String, Object> collision = new LinkedHashMap<>();
        collision.put("Bearer abcdefghijklmnopqrstuvwxyz", "first");
        collision.put("Bearer 12345678901234567890123456", "second");

        assertSanitizationFailsWithoutCause(collision);
    }

    @Test
    void failsClosedWhenDepthOrNodeLimitsAreExceeded() {
        List<Object> nested = List.of(List.of(List.of("value")));

        assertSanitizationFailsWithoutCause(
                nested, new TraversalLimits(1, 100));
        assertSanitizationFailsWithoutCause(
                List.of("one", "two", "three"), new TraversalLimits(10, 2));
    }

    @Test
    void failsClosedForUnsupportedPlatformObjectsAndOversizedCandidates() {
        assertSanitizationFailsWithoutCause(new StringBuilder("do not inspect"));
        assertSanitizationFailsWithoutCause("x".repeat(65_537));
    }

    @Test
    void rejectsUnsupportedComplexMapKeysInsteadOfReturningThemUnchanged() {
        Map<Object, Object> input = new LinkedHashMap<>();
        input.put(new Object(), "value");

        assertSanitizationFailsWithoutCause(input);
    }

    @Test
    void nullInputProducesEmptyResult() {
        SanitizationResult result = sanitizer.sanitize(null);

        assertNull(result.value());
        assertEquals(0, result.visitedNodes());
        assertEquals(0, result.maskedValues());
    }

    private void assertSanitizationFailsWithoutCause(Object input) {
        assertSanitizationFailsWithoutCause(input, TraversalLimits.defaults());
    }

    private void assertSanitizationFailsWithoutCause(Object input, TraversalLimits limits) {
        SecretShieldException exception = assertThrows(
                SecretShieldException.class, () -> sanitizer.sanitize(input, limits));
        assertEquals("Sanitization failed; no sanitized result was produced", exception.getMessage());
        assertNull(exception.getCause());
        assertFalse(exception.toString().contains(PASSWORD));
    }

    private static final class Credentials {
        private String password = PASSWORD;
        private String privateKey = "private-key-material";
        private char[] characterSecret = "character-secret".toCharArray();
    }

    private static final class SharedPayload {
        private String label = "visible";
    }
}

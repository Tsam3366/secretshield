package io.github.secretshield.core.detector;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionResult;
import io.github.secretshield.api.model.DataLocation;
import io.github.secretshield.api.model.SecretCategory;
import io.github.secretshield.api.model.SecretFinding;
import io.github.secretshield.core.detector.rules.FieldNameDetectionRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DefaultSecretDetectorTest {

    private final FieldNameDetectionRule fieldNameRule = new FieldNameDetectionRule();

    @Test
    void detectsPasswordFieldWithoutReturningCandidateValue() {
        String secret = "do-not-leak-this-password";
        DetectionInput input = new DetectionInput(
                "password", new DataLocation("account.password"), secret);

        DetectionResult result = new DefaultSecretDetector(List.of(fieldNameRule)).detect(input);

        assertEquals(1, result.findings().size());
        SecretFinding finding = result.findings().getFirst();
        assertEquals(SecretCategory.PASSWORD, finding.category());
        assertEquals("account.password", finding.location().path());
        assertFalse(finding.toString().contains(secret));
        assertFalse(input.toString().contains(secret));
        assertFalse(input.toString().contains("password"));
        assertFalse(result.toString().contains(secret));
    }

    @Test
    void ignoresGenericKeyAndIdFields() {
        DefaultSecretDetector detector = new DefaultSecretDetector(List.of(fieldNameRule));

        assertFalse(detector.detect(new DetectionInput(
                "key", new DataLocation("config.key"), "abc123")).hasFindings());
        assertFalse(detector.detect(new DetectionInput(
                "id", new DataLocation("user.id"), "12345")).hasFindings());
    }

    @Test
    void matchesNamesWithoutCaseSensitivity() {
        DetectionResult result = new DefaultSecretDetector(List.of(fieldNameRule))
                .detect(new DetectionInput(
                        "ACCESS_TOKEN", new DataLocation("session.ACCESS_TOKEN"), "token"));

        assertEquals(SecretCategory.ACCESS_TOKEN, result.findings().getFirst().category());
    }

    @Test
    void ignoresMissingFieldNameAndEmptyCandidate() {
        DefaultSecretDetector detector = new DefaultSecretDetector(List.of(fieldNameRule));

        assertFalse(detector.detect(new DetectionInput(
                null, new DataLocation("value"), "secret")).hasFindings());
        assertFalse(detector.detect(new DetectionInput(
                "password", new DataLocation("password"), "")).hasFindings());
    }

    @Test
    void resultFindingsAreImmutable() {
        DetectionResult result = new DetectionResult(List.of());
        assertThrows(UnsupportedOperationException.class,
                () -> result.findings().add(null));
    }
}

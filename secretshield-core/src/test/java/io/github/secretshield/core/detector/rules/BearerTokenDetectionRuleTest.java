package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.model.DataLocation;
import io.github.secretshield.api.model.SecretCategory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BearerTokenDetectionRuleTest {
    private final BearerTokenDetectionRule rule = new BearerTokenDetectionRule();

    @Test
    void detectsBearerCredentialCaseInsensitively() {
        String value = "bEaReR  abcdefghijklmnopqrstuvwxyz012345";
        var finding = rule.detect(input(value)).orElseThrow();

        assertEquals(SecretCategory.ACCESS_TOKEN, finding.category());
        assertEquals(BearerTokenDetectionRule.RULE_ID, finding.ruleId());
        assertFalse(finding.toString().contains(value));
    }

    @Test
    void rejectsShortMalformedAndNonBearerValues() {
        assertTrue(rule.detect(input("Bearer short")).isEmpty());
        assertTrue(rule.detect(input("Basic abcdefghijklmnopqrstuvwxyz")).isEmpty());
        assertTrue(rule.detect(input("Bearer abcdefghijklmnop qr")).isEmpty());
    }

    private static DetectionInput input(String value) {
        return new DetectionInput("authorization", new DataLocation("headers.authorization"), value);
    }
}

package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.model.DataLocation;
import io.github.secretshield.api.model.SecretCategory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PemPrivateKeyDetectionRuleTest {
    private final PemPrivateKeyDetectionRule rule = new PemPrivateKeyDetectionRule();

    @Test
    void detectsCompletePemPrivateKeyBlockWithoutReturningContents() {
        String pem = "-----BEGIN RSA PRIVATE KEY-----\nprivate-material\n"
                + "-----END RSA PRIVATE KEY-----";
        var finding = rule.detect(input(pem)).orElseThrow();

        assertEquals(SecretCategory.PRIVATE_KEY, finding.category());
        assertEquals(PemPrivateKeyDetectionRule.RULE_ID, finding.ruleId());
        assertFalse(finding.toString().contains("private-material"));
    }

    @Test
    void recognizesOpenSshPrivateKeyAndRejectsHeaderOnlyText() {
        assertTrue(rule.detect(input("-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n"
                + "-----END OPENSSH PRIVATE KEY-----")).isPresent());
        assertTrue(rule.detect(input("-----BEGIN PRIVATE KEY-----")).isEmpty());
    }

    private static DetectionInput input(String value) {
        return new DetectionInput("key", new DataLocation("config.key"), value);
    }
}

package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.model.DataLocation;
import io.github.secretshield.api.model.SecretCategory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FieldNameDetectionRuleTest {
    private final FieldNameDetectionRule rule = new FieldNameDetectionRule();

    @Test
    void classifiesSupportedCredentialNames() {
        assertCategory("password", "value", SecretCategory.PASSWORD);
        assertCategory("api_key", "value", SecretCategory.API_KEY);
        assertCategory("refresh-token", "value", SecretCategory.REFRESH_TOKEN);
        assertCategory("privateKey", "value", SecretCategory.PRIVATE_KEY);
    }

    @Test
    void doesNotTreatArbitraryNamesAsSecrets() {
        assertTrue(rule.detect(input("key", "value")).isEmpty());
        assertTrue(rule.detect(input("id", "value")).isEmpty());
        assertTrue(rule.detect(input("monkey", "value")).isEmpty());
        assertTrue(rule.detect(input("secretaryName", "value")).isEmpty());
    }

    private void assertCategory(String field, String value, SecretCategory expected) {
        assertEquals(expected, rule.detect(input(field, value)).orElseThrow().category());
    }

    private DetectionInput input(String field, String value) {
        return new DetectionInput(field, new DataLocation("root." + field), value);
    }
}

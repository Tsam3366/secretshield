package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.model.DataLocation;
import io.github.secretshield.api.model.SecretCategory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EmailAddressDetectionRuleTest {
    private final EmailAddressDetectionRule rule = new EmailAddressDetectionRule();

    @Test
    void detectsCommonEmailAddressInText() {
        String value = "Contact support at jane.doe+ops@example-domain.com today";
        var finding = rule.detect(input(value)).orElseThrow();

        assertEquals(SecretCategory.EMAIL, finding.category());
        assertEquals(EmailAddressDetectionRule.RULE_ID, finding.ruleId());
        assertFalse(finding.toString().contains("jane.doe"));
    }

    @Test
    void rejectsMalformedAddresses() {
        assertTrue(rule.detect(input("not-an-email")).isEmpty());
        assertTrue(rule.detect(input("a..b@example.com")).isEmpty());
        assertTrue(rule.detect(input(".user@example.com")).isEmpty());
        assertTrue(rule.detect(input("user@-example.com")).isEmpty());
        assertTrue(rule.detect(input("user@example.c")).isEmpty());
    }

    @Test
    void detectsEmailFollowedBySentencePunctuation() {
        assertTrue(rule.detect(input("Contact jane@example.com.")).isPresent());
        assertTrue(rule.detect(input("Contact jane@example.com..")).isEmpty());
    }

    @Test
    void handlesOverlongCandidateWithoutBacktrackingRegex() {
        String value = "a".repeat(100_000) + "@example.com";
        assertTrue(rule.detect(input(value)).isEmpty());
    }

    private static DetectionInput input(String value) {
        return new DetectionInput("value", new DataLocation("payload.value"), value);
    }
}

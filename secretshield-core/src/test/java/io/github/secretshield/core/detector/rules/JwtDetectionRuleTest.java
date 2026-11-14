package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.model.DataLocation;
import io.github.secretshield.api.model.SecretCategory;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtDetectionRuleTest {
    private final JwtDetectionRule rule = new JwtDetectionRule();

    @Test
    void detectsCompactSignedJwtWithoutReturningToken() {
        String token = segment("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "."
                + segment("{\"sub\":\"1234567890\",\"name\":\"Jane\"}") + "."
                + "c2lnbmF0dXJl";
        var finding = rule.detect(input(token)).orElseThrow();

        assertEquals(SecretCategory.ACCESS_TOKEN, finding.category());
        assertEquals(JwtDetectionRule.RULE_ID, finding.ruleId());
        assertFalse(finding.toString().contains(token));
    }

    @Test
    void rejectsMalformedOrNonCompactValues() {
        assertTrue(rule.detect(input("not-a-jwt")).isEmpty());
        assertTrue(rule.detect(input("a.b.c.d")).isEmpty());
        assertTrue(rule.detect(input("%%%." + segment("{}") + ".signature")).isEmpty());
        assertTrue(rule.detect(input(segment("[]") + "." + segment("{}") + ".signature")).isEmpty());
    }

    private static String segment(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static DetectionInput input(String value) {
        return new DetectionInput("token", new DataLocation("request.token"), value);
    }
}

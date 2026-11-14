package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionRule;
import io.github.secretshield.api.model.SecretCategory;
import io.github.secretshield.api.model.SecretFinding;
import java.util.Optional;

/** Detects opaque bearer credentials in an Authorization header value. */
public final class BearerTokenDetectionRule implements DetectionRule {
    public static final String RULE_ID = "builtin.bearer-token";
    private static final int MIN_TOKEN_LENGTH = 20;
    private static final int MAX_TOKEN_LENGTH = 8_192;

    @Override
    public Optional<SecretFinding> detect(DetectionInput input) {
        String value = input.value();
        if (value.length() < 7 || !value.regionMatches(true, 0, "Bearer", 0, 6)
                || !isWhitespace(value.charAt(6))) {
            return Optional.empty();
        }

        int start = 6;
        while (start < value.length() && isWhitespace(value.charAt(start))) {
            start++;
        }
        int end = value.length();
        while (end > start && isWhitespace(value.charAt(end - 1))) {
            end--;
        }

        int length = end - start;
        if (length < MIN_TOKEN_LENGTH || length > MAX_TOKEN_LENGTH) {
            return Optional.empty();
        }
        for (int i = start; i < end; i++) {
            if (!isBearerCharacter(value.charAt(i))) {
                return Optional.empty();
            }
        }

        return Optional.of(new SecretFinding(
                SecretCategory.ACCESS_TOKEN, input.location(), RULE_ID, 0.96));
    }

    private static boolean isWhitespace(char c) {
        return c == ' ' || c == '\t';
    }

    // RFC 6750 b64token character set.
    private static boolean isBearerCharacter(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
                || c == '~' || c == '+' || c == '/' || c == '=';
    }
}

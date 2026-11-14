package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionRule;
import io.github.secretshield.api.model.SecretCategory;
import io.github.secretshield.api.model.SecretFinding;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Recognizes a compact, signed JWT by its bounded base64url structure.
 *
 * <p>This is structural detection only. It does not verify a signature,
 * validate claims, or establish token authenticity.</p>
 */
public final class JwtDetectionRule implements DetectionRule {
    public static final String RULE_ID = "builtin.jwt";
    private static final int MAX_TOKEN_LENGTH = 16_384;

    @Override
    public Optional<SecretFinding> detect(DetectionInput input) {
        String value = input.value();
        if (value.length() < 20 || value.length() > MAX_TOKEN_LENGTH) {
            return Optional.empty();
        }

        int firstDot = value.indexOf('.');
        if (firstDot <= 0) {
            return Optional.empty();
        }
        int secondDot = value.indexOf('.', firstDot + 1);
        if (secondDot <= firstDot + 1 || secondDot == value.length() - 1
                || value.indexOf('.', secondDot + 1) >= 0) {
            return Optional.empty();
        }

        String header = value.substring(0, firstDot);
        String payload = value.substring(firstDot + 1, secondDot);
        String signature = value.substring(secondDot + 1);
        if (!isBase64Url(header) || !isBase64Url(payload) || !isBase64Url(signature)) {
            return Optional.empty();
        }

        try {
            if (!isJsonObjectSegment(header) || !isJsonObjectSegment(payload)) {
                return Optional.empty();
            }
        } catch (IllegalArgumentException malformedBase64) {
            return Optional.empty();
        }

        return Optional.of(new SecretFinding(
                SecretCategory.ACCESS_TOKEN, input.location(), RULE_ID, 0.98));
    }

    private static boolean isBase64Url(String segment) {
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_')) {
                return false;
            }
        }
        return !segment.isEmpty();
    }

    private static boolean isJsonObjectSegment(String segment) {
        byte[] decoded = Base64.getUrlDecoder().decode(segment);
        if (decoded.length < 2) {
            return false;
        }
        String text = new String(decoded, StandardCharsets.UTF_8).strip();
        return text.startsWith("{") && text.endsWith("}");
    }
}

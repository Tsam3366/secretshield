package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionRule;
import io.github.secretshield.api.model.SecretCategory;
import io.github.secretshield.api.model.SecretFinding;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Detects sensitive fields using a conservative allow-list of exact names.
 *
 * <p>Generic names such as {@code key}, {@code id}, and {@code value} are
 * deliberately excluded to avoid broad false positives.</p>
 */
public final class FieldNameDetectionRule implements DetectionRule {
    public static final String RULE_ID = "builtin.field-name";

    private static final Map<String, SecretCategory> SENSITIVE_NAMES = Map.ofEntries(
            Map.entry("password", SecretCategory.PASSWORD),
            Map.entry("passwd", SecretCategory.PASSWORD),
            Map.entry("pwd", SecretCategory.PASSWORD),
            Map.entry("apikey", SecretCategory.API_KEY),
            Map.entry("api_key", SecretCategory.API_KEY),
            Map.entry("api-key", SecretCategory.API_KEY),
            Map.entry("accesstoken", SecretCategory.ACCESS_TOKEN),
            Map.entry("access_token", SecretCategory.ACCESS_TOKEN),
            Map.entry("access-token", SecretCategory.ACCESS_TOKEN),
            Map.entry("refreshtoken", SecretCategory.REFRESH_TOKEN),
            Map.entry("refresh_token", SecretCategory.REFRESH_TOKEN),
            Map.entry("refresh-token", SecretCategory.REFRESH_TOKEN),
            Map.entry("privatekey", SecretCategory.PRIVATE_KEY),
            Map.entry("private_key", SecretCategory.PRIVATE_KEY),
            Map.entry("private-key", SecretCategory.PRIVATE_KEY),
            Map.entry("clientsecret", SecretCategory.CUSTOM),
            Map.entry("client_secret", SecretCategory.CUSTOM),
            Map.entry("client-secret", SecretCategory.CUSTOM)
    );

    @Override
    public Optional<SecretFinding> detect(DetectionInput input) {
        if (input.fieldName() == null || input.fieldName().isBlank()
                || input.value().isEmpty()) {
            return Optional.empty();
        }

        String normalized = input.fieldName().trim().toLowerCase(Locale.ROOT);
        SecretCategory category = SENSITIVE_NAMES.get(normalized);
        if (category == null) {
            return Optional.empty();
        }

        return Optional.of(new SecretFinding(category, input.location(), RULE_ID, 0.95));
    }
}

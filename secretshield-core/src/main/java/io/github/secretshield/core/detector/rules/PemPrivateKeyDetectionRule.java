package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionRule;
import io.github.secretshield.api.model.SecretCategory;
import io.github.secretshield.api.model.SecretFinding;
import java.util.List;
import java.util.Optional;

/** Detects complete, recognized PEM private-key blocks. */
public final class PemPrivateKeyDetectionRule implements DetectionRule {
    public static final String RULE_ID = "builtin.pem-private-key";

    private static final List<String> KEY_TYPES = List.of(
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "OPENSSH PRIVATE KEY"
    );

    @Override
    public Optional<SecretFinding> detect(DetectionInput input) {
        String value = input.value();
        for (String keyType : KEY_TYPES) {
            String begin = "-----BEGIN " + keyType + "-----";
            String end = "-----END " + keyType + "-----";
            int beginIndex = value.indexOf(begin);
            if (beginIndex >= 0 && value.indexOf(end, beginIndex + begin.length()) >= 0) {
                return Optional.of(new SecretFinding(
                        SecretCategory.PRIVATE_KEY, input.location(), RULE_ID, 1.0));
            }
        }
        return Optional.empty();
    }
}

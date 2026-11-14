package io.github.secretshield.core.detector.rules;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionRule;
import io.github.secretshield.api.model.SecretCategory;
import io.github.secretshield.api.model.SecretFinding;
import java.util.Optional;

/**
 * Finds common ASCII email-address forms without a backtracking regular expression.
 *
 * <p>This intentionally does not attempt full RFC 5322 or internationalized
 * address validation.</p>
 */
public final class EmailAddressDetectionRule implements DetectionRule {
    public static final String RULE_ID = "builtin.email-address";
    private static final int MAX_LOCAL_LENGTH = 64;
    private static final int MAX_DOMAIN_LENGTH = 253;

    @Override
    public Optional<SecretFinding> detect(DetectionInput input) {
        String value = input.value();
        int at = value.indexOf('@');
        while (at >= 0) {
            if (isEmailAt(value, at)) {
                return Optional.of(new SecretFinding(
                        SecretCategory.EMAIL, input.location(), RULE_ID, 0.90));
            }
            at = value.indexOf('@', at + 1);
        }
        return Optional.empty();
    }

    private static boolean isEmailAt(String value, int at) {
        int localStart = at;
        while (localStart > 0 && at - localStart < MAX_LOCAL_LENGTH
                && isLocalCharacter(value.charAt(localStart - 1))) {
            localStart--;
        }
        if (localStart == at
                || (localStart > 0 && isLocalCharacter(value.charAt(localStart - 1)))) {
            return false;
        }

        int localLength = at - localStart;
        if (localLength > MAX_LOCAL_LENGTH
                || value.charAt(localStart) == '.'
                || value.charAt(at - 1) == '.') {
            return false;
        }
        for (int i = localStart + 1; i < at; i++) {
            if (value.charAt(i) == '.' && value.charAt(i - 1) == '.') {
                return false;
            }
        }

        int domainStart = at + 1;
        int domainEnd = domainStart;
        while (domainEnd < value.length()
                && domainEnd - domainStart <= MAX_DOMAIN_LENGTH
                && isDomainCharacter(value.charAt(domainEnd))) {
            domainEnd++;
        }
        if (domainEnd == domainStart
                || domainEnd - domainStart > MAX_DOMAIN_LENGTH
                || (domainEnd < value.length()
                    && isDomainCharacter(value.charAt(domainEnd)))) {
            return false;
        }

        return hasValidDomainLabels(value, domainStart, domainEnd);
    }

    private static boolean hasValidDomainLabels(String value, int start, int end) {
        int labelStart = start;
        int dotCount = 0;
        int lastLabelStart = start;
        int lastLabelLength = 0;

        for (int i = start; i <= end; i++) {
            if (i == end || value.charAt(i) == '.') {
                int labelLength = i - labelStart;
                if (labelLength == 0 || labelLength > 63
                        || value.charAt(labelStart) == '-'
                        || value.charAt(i - 1) == '-') {
                    return false;
                }
                if (i < end) {
                    dotCount++;
                }
                lastLabelStart = labelStart;
                lastLabelLength = labelLength;
                labelStart = i + 1;
            } else {
                char c = value.charAt(i);
                if (!isAsciiAlphaNumeric(c) && c != '-') {
                    return false;
                }
            }
        }

        if (dotCount == 0 || lastLabelLength < 2) {
            return false;
        }
        for (int i = lastLabelStart; i < end; i++) {
            char c = value.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isLocalCharacter(char c) {
        return isAsciiAlphaNumeric(c) || ".!#$%&'*+/=?^_".indexOf(c) >= 0
                || c == 96 || c == '{' || c == '|' || c == '}' || c == '~' || c == '-';
    }

    private static boolean isDomainCharacter(char c) {
        return isAsciiAlphaNumeric(c) || c == '-' || c == '.';
    }

    private static boolean isAsciiAlphaNumeric(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9');
    }
}

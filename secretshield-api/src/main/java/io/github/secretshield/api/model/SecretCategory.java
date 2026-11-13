package io.github.secretshield.api.model;

/**
 * Broad classification of sensitive information recognized by SecretShield.
 *
 * <p>Categories describe the type of data, not the value itself.</p>
 */
public enum SecretCategory {
    PASSWORD,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    API_KEY,
    DATABASE_CREDENTIAL,
    PRIVATE_KEY,
    EMAIL,
    PHONE_NUMBER,
    PAYMENT_CARD,
    PERSONAL_DATA,
    CUSTOM,
    UNKNOWN
}

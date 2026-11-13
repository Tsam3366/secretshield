package io.github.secretshield.api.model;

import java.util.Objects;

/**
 * Identifies where a finding was detected without storing the detected value.
 *
 * @param path logical path such as {@code user.credentials.password}
 */
public record DataLocation(String path) {
    public DataLocation {
        Objects.requireNonNull(path, "path must not be null");
        if (path.isBlank()) {
            throw new IllegalArgumentException("path must not be blank");
        }
    }

    @Override
    public String toString() {
        return "DataLocation[path=" + path + "]";
    }
}

package org.mazhai.aran.iam.auth;

public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        String role
) {
}

package org.mazhai.aran.iam.auth;

import org.mazhai.aran.iam.security.JwtService;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final JwtService jwtService;

    public AuthService(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    public LoginResponse adminLogin(LoginRequest request) {
        validateCredentials(request);
        String role = "ROLE_SUPER_ADMIN";
        String token = jwtService.generateToken(request.email(), role);
        return new LoginResponse(token, "Bearer", jwtService.getExpirationSeconds(), role);
    }

    public LoginResponse tenantLogin(LoginRequest request) {
        validateCredentials(request);
        String role = "ROLE_TENANT";
        String token = jwtService.generateToken(request.email(), role);
        return new LoginResponse(token, "Bearer", jwtService.getExpirationSeconds(), role);
    }

    private void validateCredentials(LoginRequest request) {
        if (request.password().length() < 8) {
            throw new IllegalArgumentException("Invalid credentials");
        }
    }
}

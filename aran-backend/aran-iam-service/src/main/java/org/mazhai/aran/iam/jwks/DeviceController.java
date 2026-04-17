package org.mazhai.aran.iam.jwks;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * DeviceController — device registration endpoint for E2E testing.
 *
 * In production, device registration happens during onboarding via the tenant service.
 * This endpoint is primarily for E2E testing to seed the DeviceKeyStore with test keys.
 *
 * Endpoint: POST /api/v1/auth/device/register
 */
@RestController
@RequestMapping("/api/v1/auth/device")
public class DeviceController {

    private final DeviceKeyStore deviceKeyStore;

    public DeviceController(DeviceKeyStore deviceKeyStore) {
        this.deviceKeyStore = deviceKeyStore;
    }

    @PostMapping("/register")
    public ResponseEntity<RegistrationResponse> register(@Valid @RequestBody RegistrationRequest request) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(request.publicKeyB64());
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(spec);
            
            deviceKeyStore.register(request.keyId(), request.appId(), publicKey);
            
            return ResponseEntity.ok(new RegistrationResponse("REGISTERED", request.keyId()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                    .body(new RegistrationResponse("INVALID_KEY: " + e.getMessage(), request.keyId()));
        }
    }

    public record RegistrationRequest(
            @JsonProperty("key_id") String keyId,
            @JsonProperty("app_id") String appId,
            @JsonProperty("public_key_b64") String publicKeyB64
    ) {}

    public record RegistrationResponse(
            String status,
            String keyId
    ) {}
}

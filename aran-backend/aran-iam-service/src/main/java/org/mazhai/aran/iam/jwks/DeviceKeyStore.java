package org.mazhai.aran.iam.jwks;

import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Collection;

/**
 * DeviceKeyStore — in-memory registry of device EC public keys.
 *
 * In production this is backed by the tenant database.
 * Each key is registered during device onboarding (the SDK sends
 * X-Aran-Public-Key during the first authenticated request).
 *
 * The JWKS endpoint serves all active keys so Envoy's jwt_authn
 * filter can verify Sigil JWTs signed by any registered device.
 *
 * Key lifecycle:
 *   register()   — called by DeviceRegistrationFilter on first request
 *   revoke()     — called on logout / remote wipe
 *   activeKeys() — polled by JwksController every 300s via Envoy cache
 */
@Component
public class DeviceKeyStore {

    private final ConcurrentHashMap<String, DeviceKey> keys = new ConcurrentHashMap<>();

    public void register(String keyId, String appId, PublicKey publicKey) {
        keys.put(keyId, new DeviceKey(keyId, appId, publicKey, System.currentTimeMillis()));
    }

    public void revoke(String keyId) {
        keys.remove(keyId);
    }

    public Collection<DeviceKey> activeKeys() {
        return keys.values();
    }

    public record DeviceKey(
            String keyId,
            String appId,
            PublicKey publicKey,
            long registeredAt
    ) {}
}

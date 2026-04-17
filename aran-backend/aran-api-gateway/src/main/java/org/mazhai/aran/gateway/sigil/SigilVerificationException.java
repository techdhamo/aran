package org.mazhai.aran.gateway.sigil;

public class SigilVerificationException extends RuntimeException {
    public SigilVerificationException(String message) {
        super(message);
    }
    public SigilVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}

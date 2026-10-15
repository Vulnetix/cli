package com.acme.security;

public class Checks {
    public boolean verifySignature(byte[] payload, byte[] sig) {
        try {
            return engine.verify(payload, sig);
        } catch (java.security.SignatureException e) {
            return false;
        }
    }

    public boolean isRetryable(Exception failure) {
        try {
            classify(failure);
        } catch (RuntimeException e) {
            return true;
        }
        return false;
    }

    public boolean deleteQuietly(java.io.File f) {
        try {
            java.nio.file.Files.delete(f.toPath());
        } catch (java.io.IOException e) {
            return true;
        }
        return true;
    }

    public boolean isValid(String s) {
        if (s == null) {
            return false;
        }
        return true;
    }
}

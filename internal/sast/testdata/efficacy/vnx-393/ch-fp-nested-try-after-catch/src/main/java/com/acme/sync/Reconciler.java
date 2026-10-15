package com.acme.sync;

public class Reconciler {
    public boolean verifyAndApply(Change c) {
        try {
            signer.check(c);
        } catch (SignatureException e) {
            audit.reject(c, e);
            return false;
        }
        apply(c);
        return true;
    }

    // In a catch, never return ResponseEntity.ok(...) for a failure.
    public String describe() {
        return "catch (Exception e) { return ResponseEntity.ok(); }";
    }
}

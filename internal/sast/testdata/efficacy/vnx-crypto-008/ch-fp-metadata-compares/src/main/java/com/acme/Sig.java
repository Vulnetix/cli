package com.acme;

public class Sig {
    boolean rsa(String signatureAlgorithm) {
        return "SHA256withRSA".equals(signatureAlgorithm);
    }
    boolean same(java.security.MessageDigest md, byte[] a, byte[] b) {
        return java.security.MessageDigest.isEqual(a, b);
    }
}

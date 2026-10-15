package com.example.auth;

public class Docs {
    // MessageDigest.getInstance("MD5") is broken; use SHA-256.
    static final String NOTE = "MD5 and SHA-1 are not allowed";
    static final String HEADER = "Content-MD5";
    void log() {
        System.out.println("rejecting MessageDigest.getInstance(\"MD5\") callers");
    }
}

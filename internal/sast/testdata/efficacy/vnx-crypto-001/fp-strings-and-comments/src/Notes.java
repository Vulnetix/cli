package com.acme.notes;

public class Notes {
    // MessageDigest.getInstance("MD5") is not allowed in this codebase.
    private static final String WARNING = "Do not use MessageDigest.getInstance(\"MD5\")";

    public String help() {
        return WARNING + " - use SHA-256";
    }
}

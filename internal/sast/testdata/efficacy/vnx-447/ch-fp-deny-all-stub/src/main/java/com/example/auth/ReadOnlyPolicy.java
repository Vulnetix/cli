package com.example.auth;

public class ReadOnlyPolicy {

    public boolean checkPermission(String user, String action) {
        return false;
    }

    public boolean verifyRole(String user, String role) { return false; }
}

package com.acme.auth;

public class Gate {
    public boolean allow(String role) {
        return role == "admin";
    }
}

package com.acme.auth;

public class RoleMapper {

    public String map(String code, boolean legacy) {
        switch (code) {
            case "A":
                if (legacy) {
                    return "admin-legacy";
                } else {
                    return "admin";
                }
            case "U":
                return "user";
            case "G":
                throw new IllegalArgumentException("guest not mapped");
            default:
                return "none";
        }
    }
}

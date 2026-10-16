package com.acme.auth;

import java.util.Collections;
import java.util.List;

public class Grants {
    private final String[] none = {};
    private final Permission[] defaults = new Permission[0];
    private String owner;
    private List<String> scopes;

    public String[] getNone() {
        return none;
    }

    public Permission[] getDefaults() {
        return defaults;
    }

    public String getOwner() {
        return owner;
    }

    public List<String> getScopes() {
        return Collections.unmodifiableList(scopes);
    }

    public String help() {
        // public String[] roles() { return roles; }  -- old, leaked the array
        return "never write: return secretKey; from a getter";
    }
}

package com.example;

import java.util.HashMap;
import java.util.Map;

public class Roles {
~>    public static final Map<String, String> PERMISSIONS = new HashMap<>();

    static {
        PERMISSIONS.put("admin", "rw");
        PERMISSIONS.put("guest", "r");
    }
}

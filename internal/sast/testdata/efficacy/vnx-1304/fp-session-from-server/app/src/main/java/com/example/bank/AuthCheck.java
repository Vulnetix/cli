package com.example.bank;

import org.json.JSONObject;

public class AuthCheck {
    boolean check(JSONObject response) throws Exception {
        boolean authenticated = response.getBoolean("authenticated");
        return authenticated && response.getString("role").equals("admin");
    }
}

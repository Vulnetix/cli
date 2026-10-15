package com.acme.repo;

import java.util.Map;

public class Payloads {
    void fill(Map<String, String> params) {
        params.put("username", "tom' AND substring(password,1,1)='t");
        params.put("label", "UPPER(x) in the label is fine");
        String sql = "SELECT id FROM users WHERE email = ? AND created > ?";
    }
}

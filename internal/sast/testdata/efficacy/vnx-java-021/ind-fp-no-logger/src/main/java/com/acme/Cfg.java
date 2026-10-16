package com.acme;
public class Cfg {
    String password = System.getenv("DB_PASSWORD");
    String tokenUrl = "https://idp.example.com/token";
    void store(String secret) { vault.put("secret", secret); }
    Object vault;
}

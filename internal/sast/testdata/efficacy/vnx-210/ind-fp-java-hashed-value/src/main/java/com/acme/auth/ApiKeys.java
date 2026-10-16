package com.acme.auth;

public class ApiKeys {
    public ApiKey require(String apiKey) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("apiKey header missing");
        }
        ApiKey key = repo.findByDigest(sha256(apiKey));
        if (key == null) {
            throw new SecurityException("unknown api key with digest " + sha256(apiKey));
        }
        return key;
    }
}

package com.acme.auth;

interface Defaults {
    String tokenSecret = "unused";
}

@Component
public class Config {
    @Value("${app.secret}")
    String appSecret;
    @Inject String apiToken;
    // String rootPassword;
}

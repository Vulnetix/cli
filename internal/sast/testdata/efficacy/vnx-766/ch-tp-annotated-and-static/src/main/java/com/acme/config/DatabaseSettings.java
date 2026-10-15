package com.acme.config;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DatabaseSettings {
    public String url;

~>    @JsonProperty("pwd") public String dbPassword;

~>    public static String apiKey = System.getenv("ACME_API_KEY");

~>    public transient char[] passphrase;

    private int poolSize = 10;
}

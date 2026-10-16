package com.acme.net;

public class Client {
    protected String apiToken;
    public String password;

    class Retry {
        String header() {
            return "Bearer " + apiToken;
        }
    }

    // class Leaky { String k() { return secretKey; } }
}

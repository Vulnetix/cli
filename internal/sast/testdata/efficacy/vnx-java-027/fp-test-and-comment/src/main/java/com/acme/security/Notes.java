package com.acme.security;

public class Notes {
    // Do not call http.headers().frameOptions().disable() in production.
    /* .headers(headers -> headers.disable()) */
    static final String WARNING = "headers().disable() removes every security header";
}

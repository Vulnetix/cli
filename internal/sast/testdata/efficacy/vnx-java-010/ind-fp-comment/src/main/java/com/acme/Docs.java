package com.acme;

public class Docs {
    // Do not call http.csrf().disable() on browser-facing apps
    static final String ADVICE = "never use csrf(AbstractHttpConfigurer::disable) here";
}

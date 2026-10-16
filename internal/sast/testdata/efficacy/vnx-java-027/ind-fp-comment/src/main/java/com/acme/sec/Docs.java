package com.acme.sec;

public class Docs {
    // Never call http.headers().disable() in production
    /* http.headers().frameOptions().disable(); */
    static final String WARNING = "do not use headers().disable() or frameOptions().disable()";
}

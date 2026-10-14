package com.acme.docs;

public class SecurityAdvice {
    // Never call http.csrf().disable() for a browser-facing application.
    /* .csrf(csrf -> csrf.disable()) is only acceptable for token APIs */
    static final String WARNING = "do not use .csrf().disable() here";

    void csrfDisabled() {
        boolean csrfDisabled = false;
        disableCsrfLogging();
    }

    void disableCsrfLogging() {
    }
}

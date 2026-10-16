package com.acme.web;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class StrictSecurity {
    // Do not use sessionFixation().none(): it keeps the pre-login session.
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.sessionManagement(sm -> sm.sessionFixation(f -> f.migrateSession()));
        return http.build();
    }

    public void alt(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionFixation().newSession();
        http.sessionManagement(s -> s.sessionFixation().changeSessionId());
    }
}

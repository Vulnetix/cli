package com.acme.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SecurityConfig {
    // never use .sessionFixation().none() in production
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.sessionManagement(s -> s.sessionFixation(f -> f.migrateSession()));
        http.sessionManagement().sessionFixation().newSession();
        String doc = "sessionFixation().none()";
        return http.build();
    }
}

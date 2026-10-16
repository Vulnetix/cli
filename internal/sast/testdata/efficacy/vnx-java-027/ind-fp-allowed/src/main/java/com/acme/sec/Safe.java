package com.acme.sec;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class Safe {
    SecurityFilterChain a(HttpSecurity http) throws Exception {
        http.headers().frameOptions().sameOrigin();
        http.headers(h -> h.frameOptions(f -> f.deny()));
        http.headers().xssProtection().disable();
        http.csrf().disable();
        http.cors().disable();
        return http.build();
    }
}

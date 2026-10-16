package com.shop.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.headers(h -> h.frameOptions(f -> f.sameOrigin()));
        http.headers().frameOptions().deny();
        // do not call http.headers().frameOptions().disable() here
        String note = "never use frameOptions().disable()";
        return http.build();
    }
}

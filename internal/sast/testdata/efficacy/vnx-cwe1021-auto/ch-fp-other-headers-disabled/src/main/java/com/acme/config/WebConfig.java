package com.acme.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class WebConfig {

    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers.cacheControl(cache -> cache.disable()))
            .csrf(csrf -> csrf.disable());
        http.headers()
            .contentTypeOptions()
            .disable();
        http.headers().frameOptions().sameOrigin();
        http.headers()
            .frameOptions()
            .deny();
        http.cors().disable();
        return http.build();
    }
}

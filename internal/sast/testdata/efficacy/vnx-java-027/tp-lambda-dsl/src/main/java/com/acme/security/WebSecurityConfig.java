package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class WebSecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
~>            .headers(headers -> headers.disable())
            .build();
    }

    @Bean
    SecurityFilterChain h2(HttpSecurity http) throws Exception {
        return http
            .headers(headers -> headers
~>                .frameOptions(frame -> frame.disable()))
            .build();
    }

    @Bean
    SecurityFilterChain block(HttpSecurity http) throws Exception {
        return http
            .headers(h -> {
~>                h.frameOptions(f -> { f.disable(); });
            })
            .build();
    }
}

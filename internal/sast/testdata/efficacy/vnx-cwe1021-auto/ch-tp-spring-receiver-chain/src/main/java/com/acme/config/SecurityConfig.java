package com.acme.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
~>        http.headers()
            .disable();
        http.authorizeRequests().anyRequest().authenticated();
        return http.build();
    }

    @Bean
    SecurityFilterChain embedChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
~>                .frameOptions(frame -> frame.disable())
            );
        return http.build();
    }
}

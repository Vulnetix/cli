package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class EdgeSecurityConfig {
    @Bean
    SecurityFilterChain edge(HttpSecurity http) throws Exception {
        return http
            .headers(headers -> headers
~>                .httpStrictTransportSecurity(hsts -> hsts.disable())
~>                .contentTypeOptions(c -> c.disable()))
            .build();
    }

    void legacy(HttpSecurity http) throws Exception {
~>        http.headers().httpStrictTransportSecurity().disable();
    }
}

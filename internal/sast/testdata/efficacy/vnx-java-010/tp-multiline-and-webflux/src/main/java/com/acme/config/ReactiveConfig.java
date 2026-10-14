package com.acme.config;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

public class ReactiveConfig {
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http
~>            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .formLogin(f -> {})
            .build();
    }

    void legacy(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        http
~>            .csrf()
                .disable()
            .httpBasic();
    }

    void block(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
~>        http.csrf(c ->
                c.disable());
    }
}

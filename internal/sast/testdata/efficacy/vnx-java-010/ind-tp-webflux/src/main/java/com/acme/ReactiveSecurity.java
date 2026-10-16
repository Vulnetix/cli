package com.acme;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.context.annotation.Bean;

public class ReactiveSecurity {
    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .authorizeExchange(ex -> ex.anyExchange().authenticated())
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
~>            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .build();
    }
}

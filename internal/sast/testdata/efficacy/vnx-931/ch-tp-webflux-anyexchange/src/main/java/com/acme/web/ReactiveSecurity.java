package com.acme.web;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

public class ReactiveSecurity {
    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(ex -> ex
                        .pathMatchers("/login").permitAll()
~>                        .pathMatchers("/admin/**").permitAll()
~>                        .anyExchange().permitAll())
                .build();
    }
}

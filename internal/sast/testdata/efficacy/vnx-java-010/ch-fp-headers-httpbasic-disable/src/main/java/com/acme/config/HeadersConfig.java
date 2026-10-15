package com.acme.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class HeadersConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        // CSRF stays on: never call csrf().disable() for this browser app
        http.headers(h -> h.frameOptions(f -> f.disable()))
            .httpBasic(b -> b.disable())
            .logout(l -> l.disable())
            .formLogin(f -> f.permitAll());
        return http.build();
    }
}

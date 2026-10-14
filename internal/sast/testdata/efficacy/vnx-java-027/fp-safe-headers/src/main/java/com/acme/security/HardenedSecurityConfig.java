package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class HardenedSecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)
            .headers(headers -> headers
                .frameOptions(frame -> frame.sameOrigin())
                .xssProtection(x -> x.disable())
                .contentSecurityPolicy(csp -> csp.policyDirectives("frame-ancestors 'self'")))
            .cors(c -> c.disable())
            .build();
    }

    void legacy(HttpSecurity http) throws Exception {
        http.headers().frameOptions().deny()
            .and()
            .csrf().disable();
        http.httpBasic().disable();
        http.formLogin().disable();
    }
}

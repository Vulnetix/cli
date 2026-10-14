package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class ApiSecurityConfig {
    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)
~>            .headers(AbstractHttpConfigurer::disable)
            .build();
    }

    @Bean
    SecurityFilterChain console(HttpSecurity http) throws Exception {
        return http
~>            .headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
            .build();
    }
}

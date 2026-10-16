package com.shop.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class WebSecurityConfig {
    @Bean
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
~>        http.headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
        return http.build();
    }
}

package com.acme.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.sessionManagement()
~>            .sessionFixation().none();
        return http.build();
    }

    @Bean
    SecurityFilterChain lambdaChain(HttpSecurity http) throws Exception {
~>        http.sessionManagement(s -> s.sessionFixation(f -> f.none()));
        http.sessionManagement(session -> session
~>            .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::none));
        return http.build();
    }
}

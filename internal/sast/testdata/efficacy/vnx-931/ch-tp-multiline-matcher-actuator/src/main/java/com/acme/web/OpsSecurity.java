package com.acme.web;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OpsSecurity {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(
                        "/css/**",
                        "/js/**",
                        // monitoring scrapes these
                        "/actuator/**")
~>                .permitAll()
                .requestMatchers(
                        "/login",
                        "/register")
                .permitAll()
                .requestMatchers("/admin/**")
                .hasRole("ADMIN")
                .anyRequest()
                .authenticated());
    }
}

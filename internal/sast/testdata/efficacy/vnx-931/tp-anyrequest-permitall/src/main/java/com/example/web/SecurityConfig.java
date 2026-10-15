package com.example.web;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**").permitAll()
~>                .anyRequest().permitAll());
        return http.build();
    }

    void legacy(HttpSecurity http) throws Exception {
        http.authorizeRequests()
~>            .antMatchers("/**").permitAll();
        http.authorizeRequests()
            .anyRequest()
~>            .permitAll();
    }
}

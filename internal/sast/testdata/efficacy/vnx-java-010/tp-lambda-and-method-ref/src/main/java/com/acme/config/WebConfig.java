package com.acme.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class WebConfig {
    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        return http
~>            .csrf(csrf -> csrf.disable())
            .formLogin(form -> form.loginPage("/login"))
            .build();
    }

    @Bean
    SecurityFilterChain admin(HttpSecurity http) throws Exception {
~>        http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(s -> s.maximumSessions(1));
        return http.build();
    }
}

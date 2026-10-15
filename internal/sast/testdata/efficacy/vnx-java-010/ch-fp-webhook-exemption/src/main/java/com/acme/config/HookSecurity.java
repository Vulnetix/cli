package com.acme.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class HookSecurity {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf(c -> c.ignoringRequestMatchers("/webhooks/stripe", "/webhooks/github/**"))
            .formLogin(f -> f.loginPage("/login"));
        return http.build();
    }
}

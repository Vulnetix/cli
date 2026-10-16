package com.acme;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;

public class HookSecurity {
    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http.csrf(c -> c.ignoringRequestMatchers("/webhooks/stripe"));
        http.formLogin(f -> f.loginPage("/login"));
        return http.build();
    }
}

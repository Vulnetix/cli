package com.acme;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;

public class SpaSecurity {
    @Bean
    SecurityFilterChain spa(HttpSecurity http) throws Exception {
        http.csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        http.formLogin(f -> f.loginPage("/login"));
        return http.build();
    }
}

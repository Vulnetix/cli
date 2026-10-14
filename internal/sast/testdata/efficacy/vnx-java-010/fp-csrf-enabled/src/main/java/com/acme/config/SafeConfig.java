package com.acme.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

public class SafeConfig {
    void configure(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        http.csrf().ignoringAntMatchers("/webhooks/stripe");
        http.csrf(c -> c.ignoringRequestMatchers("/actuator/health"));
        http.cors().disable();
        http.headers().frameOptions().disable();
    }
}

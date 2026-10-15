package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

public class HeaderTuning {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
                .xssProtection(xss -> xss.disable())
                .cacheControl(cache -> cache.disable())
                .frameOptions(frame -> frame.deny())
                .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN)));
        // http.headers().disable(); was needed for the old iframe embed, removed in 4.2
        return http.build();
    }

    String explain() {
        return "never call headers().disable() or frameOptions().disable() in production";
    }
}

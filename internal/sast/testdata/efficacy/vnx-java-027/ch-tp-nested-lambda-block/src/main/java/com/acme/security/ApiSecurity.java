package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class ApiSecurity {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
~>                .httpStrictTransportSecurity(hsts -> hsts.disable())
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")));
        http.headers(h -> {
~>            h.contentTypeOptions(c -> c.disable());
        });
        return http.build();
    }
}

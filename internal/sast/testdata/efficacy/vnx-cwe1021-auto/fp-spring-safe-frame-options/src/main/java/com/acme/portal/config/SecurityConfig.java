package com.acme.portal.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain consoleChain(HttpSecurity http) throws Exception {
        // Do not use .headers().frameOptions().disable() here: same origin is enough.
        http.securityMatcher("/h2-console/**")
            .headers().frameOptions().sameOrigin()
            .and()
            .csrf().disable();
        return http.build();
    }

    @Bean
    SecurityFilterChain appChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .frameOptions(frame -> frame.deny())
                .xssProtection(xss -> xss.disable())
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; frame-ancestors 'none'")))
            .csrf(c -> c.disable());
        return http.build();
    }

    @Bean
    SecurityFilterChain embedChain(HttpSecurity http) throws Exception {
        http.headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
            .headers()
                .frameOptions()
                .deny();
        return http.build();
    }

    void log(org.slf4j.Logger logger) {
        logger.info("frameOptions().disable() is not allowed in this profile");
    }
}

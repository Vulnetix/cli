package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class CustomHeadersConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.headers()
            .defaultsDisabled()
            .frameOptions().sameOrigin()
            .contentTypeOptions();
        http.headers(h -> h.cacheControl(c -> c.disable()));
        http.sessionManagement(s -> s.disable());
        http.logout().disable();
        return http.build();
    }

    void featureFlags(FeatureToggles toggles) {
        toggles.frameOptionsBanner().disable();
        toggles.headerLogging(x -> x.enable());
    }
}

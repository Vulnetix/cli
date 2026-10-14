package com.acme.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class TestSecurityConfig {
    void configure(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();
    }
}

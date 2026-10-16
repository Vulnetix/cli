package com.acme.sec;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class ConfigTest {
    void relaxed(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();
        http.headers().disable();
    }
}

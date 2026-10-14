package com.acme;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class SecurityConfigTest {

    void permissiveChain(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();
    }
}

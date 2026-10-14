package com.acme.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class IgnoreConfig {
    void configure(HttpSecurity http) throws Exception {
~>        http.csrf().ignoringAntMatchers("/**");
~>        http.csrf(c -> c.ignoringRequestMatchers("/**"));
    }
}

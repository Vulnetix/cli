package com.acme.sec;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class Cfg {
    SecurityFilterChain a(HttpSecurity http) throws Exception {
~>        http.headers(AbstractHttpConfigurer::disable);
        return http.build();
    }

    SecurityFilterChain b(HttpSecurity http) throws Exception {
        http.headers(h -> h
~>            .httpStrictTransportSecurity(hsts -> hsts.disable())
            .contentTypeOptions(Customizer.withDefaults()));
        return http.build();
    }
}

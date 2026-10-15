package com.acme.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class WebSecurity {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.formLogin(f -> f.permitAll())
~>            .csrf(c -> c.ignoringRequestMatchers(new AntPathRequestMatcher("/**")));
        return http.build();
    }
}

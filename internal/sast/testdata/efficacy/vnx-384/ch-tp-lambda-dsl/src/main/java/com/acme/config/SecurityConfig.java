package com.acme.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {

    @Bean
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
~>            .sessionManagement(sm -> sm.sessionFixation(fixation -> fixation.none()))
            .formLogin(f -> f.loginPage("/login"));
        return http.build();
    }

    @Bean
    public SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        http.sessionManagement()
            .sessionFixation()
~>            .none();
        return http.build();
    }
}

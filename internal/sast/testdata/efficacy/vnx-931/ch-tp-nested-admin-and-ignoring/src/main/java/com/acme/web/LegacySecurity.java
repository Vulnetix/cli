package com.acme.web;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class LegacySecurity {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
~>                .requestMatchers("/api/admin/**").permitAll()
~>                .requestMatchers(new AntPathRequestMatcher("/internal/**")).permitAll()
                .anyRequest().authenticated());
    }

    @Bean
    WebSecurityCustomizer skip() {
~>        return web -> web.ignoring().requestMatchers("/admin/**", "/actuator/**");
    }
}

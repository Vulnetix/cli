package com.acme.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class ModernSecurity {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http
            .headers(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(form -> form.disable());
        return http.build();
    }

    @Bean
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        http.headers()
                .frameOptions().sameOrigin()
                .and()
            .csrf().disable()
            .cors().disable();
        return http.build();
    }
}

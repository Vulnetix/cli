package com.acme;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .formLogin(f -> f.loginPage("/login").permitAll())
~>            .csrf(csrf -> csrf.disable());
        return http.build();
    }
}

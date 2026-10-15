package com.acme.web;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class AdminPortalSecurity {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
                .requestMatchers("/admin/login", "/admin/css/**", "/admin/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .formLogin(f -> f.loginPage("/admin/login").permitAll());
    }
}

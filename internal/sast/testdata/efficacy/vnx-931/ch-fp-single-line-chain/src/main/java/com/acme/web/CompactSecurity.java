package com.acme.web;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class CompactSecurity {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN").antMatchers("/public/**").permitAll().anyRequest().authenticated();
    }
}

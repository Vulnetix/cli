package com.acme;

class AdminSec {
    void configure(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        http.authorizeRequests()
~>            .antMatchers("/api/admin/**").permitAll()
            .antMatchers("/api/orders/**").hasRole("USER")
            .anyRequest().authenticated();
    }
}

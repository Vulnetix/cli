package com.example.web;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class AdminSecurity {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> {
~>            auth.requestMatchers("/admin/**").permitAll();
~>            auth.requestMatchers(HttpMethod.DELETE, "/api/users/**", "/actuator/**").permitAll();
~>            auth.requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll();
            auth.requestMatchers("/management/**")
~>                .permitAll();
            auth.anyRequest().authenticated();
        });
    }
}

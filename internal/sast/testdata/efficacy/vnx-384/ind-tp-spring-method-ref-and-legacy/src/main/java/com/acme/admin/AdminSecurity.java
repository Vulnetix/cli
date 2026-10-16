package com.acme.admin;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.SecurityFilterChain;

public class AdminSecurity {

    public SecurityFilterChain admin(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**")
            .sessionManagement(sm -> sm
~>                .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::none));
        return http.build();
    }

    @SuppressWarnings("deprecation")
    public void legacy(HttpSecurity http) throws Exception {
~>        http.sessionManagement().sessionFixation().none();
    }
}

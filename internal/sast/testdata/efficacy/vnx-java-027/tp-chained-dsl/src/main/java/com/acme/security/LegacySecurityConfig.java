package com.acme.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

public class LegacySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
~>            .headers().frameOptions().disable()
            .and()
            .authorizeRequests().anyRequest().authenticated();
    }
}

class ConsoleSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                .frameOptions()
~>                .disable()
            .and()
            .csrf().disable();
    }
}

class NoHeadersConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
~>        http.headers().disable();
    }
}

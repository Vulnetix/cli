package com.acme.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class LegacySecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtTokenFilter jwtFilter = new JwtTokenFilter();

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .and()
            .formLogin().loginPage("/signin").permitAll()
            .and()
~>            .csrf().disable()
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}

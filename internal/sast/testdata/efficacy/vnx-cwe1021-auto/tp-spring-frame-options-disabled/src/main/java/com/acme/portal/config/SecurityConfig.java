package com.acme.portal.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    // The H2 console renders in a frame, so somebody switched the header off.
    @Bean
    SecurityFilterChain consoleChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/h2-console/**")
~>            .headers().frameOptions().disable();
        return http.build();
    }

    @Bean
    SecurityFilterChain appChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
~>            .headers(headers -> headers.frameOptions(frame -> frame.disable()))
            .formLogin(form -> form.loginPage("/login"));
        return http.build();
    }

    @Bean
    SecurityFilterChain embedChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/embed/**")
~>            .headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));
        return http.build();
    }

    @Bean
    SecurityFilterChain legacyChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/legacy/**")
            .headers()
~>                .frameOptions()
                .disable()
            .and()
            .csrf().disable();
        return http.build();
    }
}

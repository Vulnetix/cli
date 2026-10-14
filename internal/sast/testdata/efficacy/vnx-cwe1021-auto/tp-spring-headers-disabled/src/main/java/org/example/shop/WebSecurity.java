package org.example.shop;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurity {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.requestMatchers("/css/**").permitAll().anyRequest().authenticated())
            .csrf(AbstractHttpConfigurer::disable)
~>            .headers(headers -> headers.disable())
            .logout(l -> l.logoutSuccessUrl("/"));
        return http.build();
    }

    @Bean
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
~>        http.securityMatcher("/api/**").headers(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public SecurityFilterChain oldChain(HttpSecurity http) throws Exception {
~>        http.securityMatcher("/old/**").headers().disable();
        return http.build();
    }
}

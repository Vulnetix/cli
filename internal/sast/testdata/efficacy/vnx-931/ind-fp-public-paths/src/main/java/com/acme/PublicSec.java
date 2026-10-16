package com.acme;

class PublicSec {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/login", "/css/**", "/js/**").permitAll()
            .requestMatchers("/actuator/health").permitAll()
            .requestMatchers("/admin/login", "/admin/css/**").permitAll()
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        ).formLogin(f -> f.permitAll()).logout(l -> l.permitAll());
    }
}

package com.acme.web

import org.springframework.security.config.web.server.ServerHttpSecurity

class PublicApi {
    fun chain(http: ServerHttpSecurity) = http
        .authorizeExchange { ex ->
            ex.pathMatchers("/public/**", "/docs/**").permitAll()
                .pathMatchers("/admin/**").hasRole("ADMIN")
                .anyExchange().authenticated()
        }
        .build()

    fun webIgnoring(web: org.springframework.security.config.annotation.web.builders.WebSecurity) {
        web.ignoring().requestMatchers("/css/**", "/images/**")
    }
}

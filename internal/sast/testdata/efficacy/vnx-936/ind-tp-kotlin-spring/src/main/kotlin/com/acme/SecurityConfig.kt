package com.acme

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {
    @Bean
    fun chain(http: HttpSecurity): SecurityFilterChain {
        http {
            formLogin { }
~>            csrf { disable() }
            authorizeRequests { authorize(anyRequest, authenticated) }
        }
        return http.build()
    }
}

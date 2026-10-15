package com.acme.config

import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

class SecurityConfig {
    @Bean
    fun chain(http: HttpSecurity): SecurityFilterChain {
        http {
            formLogin { }
            csrf {
~>                disable()
            }
        }
        return http.build()
    }
}

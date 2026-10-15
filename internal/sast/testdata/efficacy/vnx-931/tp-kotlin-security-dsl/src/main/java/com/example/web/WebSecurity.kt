package com.example.web

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke

class WebSecurity {
    fun chain(http: HttpSecurity) {
        http {
            authorizeHttpRequests {
                authorize("/login", permitAll)
~>                authorize("/admin/**", permitAll)
~>                authorize(anyRequest, permitAll)
            }
        }
    }

    fun classic(http: HttpSecurity) {
~>        http.authorizeHttpRequests { it.anyRequest().permitAll() }
    }
}

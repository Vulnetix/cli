package com.example

import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

class WebSecurity {
    @Bean
    fun web(http: HttpSecurity): SecurityFilterChain {
        http {
            cors { disable() }
            headers { frameOptions { disable() } }
            httpBasic { disable() }
            csrf { ignoringRequestMatchers("/webhooks/stripe") }
        }
        return http.build()
    }
}

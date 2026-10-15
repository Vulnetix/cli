package com.example

import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain

class ApiSecurity {
    @Bean
    fun api(http: HttpSecurity): SecurityFilterChain {
        http {
            csrf { disable() }
            sessionManagement { sessionCreationPolicy = SessionCreationPolicy.STATELESS }
            @@sample:o[a]ut[h]2R[e]so[u]rc[e]Se[r]ve[r]@@ { jwt { } }
        }
        return http.build()
    }
}

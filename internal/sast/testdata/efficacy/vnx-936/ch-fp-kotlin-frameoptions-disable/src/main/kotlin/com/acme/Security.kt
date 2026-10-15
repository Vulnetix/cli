package com.acme

import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

class Security {
    @Bean
    fun chain(http: HttpSecurity): SecurityFilterChain {
        http {
            csrf {
                ignoringRequestMatchers("/hooks/**")
            }
            headers {
                frameOptions {
                    disable()
                }
            }
            httpBasic {
                disable()
            }
        }
        return http.build()
    }
}

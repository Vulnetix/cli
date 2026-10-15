package com.example.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SecurityConfig {
    @Bean
    fun web(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests { authorize(anyRequest, authenticated) }
            formLogin { }
~>            csrf { disable() }
        }
        return http.build()
    }

    @Bean
    fun admin(http: HttpSecurity): SecurityFilterChain =
        http.securityMatcher("/admin/**")
~>            .csrf { it.disable() }
            .formLogin { }
            .build()

    @Bean
    fun legacy(http: HttpSecurity): SecurityFilterChain {
~>        http.csrf().disable()
~>        http.csrf(AbstractHttpConfigurer<*, *>::disable)
        http.formLogin()
        return http.build()
    }
}

package com.acme.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.LdapShaPasswordEncoder
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
class SecurityConfig {
    @Bean
~>    fun passwordEncoder(): PasswordEncoder = MessageDigestPasswordEncoder("MD5")

    @Bean
~>    fun ldapEncoder(): PasswordEncoder = LdapShaPasswordEncoder()
}

package com.acme.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.LdapShaPasswordEncoder
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]cr[y]pt[o][.]p[a]ss[w]or[d][.]M[d]4P[a]ss[w]or[d]En[c]od[e]r@@
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
class SecurityConfig {
    @Bean
~>    fun passwordEncoder(): PasswordEncoder = MessageDigestPasswordEncoder("MD5")

~>    fun legacySha() = MessageDigestPasswordEncoder("SHA-1")

~>    fun ntlmCompat() = Md4PasswordEncoder()

~>    fun ldap() = LdapShaPasswordEncoder()
}

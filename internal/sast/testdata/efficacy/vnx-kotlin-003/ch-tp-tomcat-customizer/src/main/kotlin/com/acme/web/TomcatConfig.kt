package com.acme.web

import org.springframework.boot.web.embedded.tomcat.TomcatContextCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class TomcatConfig {
    @Bean
    fun sessionCookieCustomizer() = TomcatContextCustomizer { context ->
~>        context.useHttpOnly = false
        context.sessionCookiePath = "/"
    }

    @Bean
    fun legacyCustomizer() = TomcatContextCustomizer {
~>        it.setUseHttpOnly(false)
    }
}

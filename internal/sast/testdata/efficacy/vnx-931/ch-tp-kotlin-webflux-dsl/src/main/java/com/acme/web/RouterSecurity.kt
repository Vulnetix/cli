package com.acme.web

import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke

class RouterSecurity {
    fun chain(http: ServerHttpSecurity) = http {
        authorizeExchange {
            authorize("/login", permitAll)
~>            authorize(anyExchange, permitAll)
        }
    }
}

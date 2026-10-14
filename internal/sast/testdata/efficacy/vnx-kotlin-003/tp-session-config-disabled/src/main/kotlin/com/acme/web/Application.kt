package com.acme.web

import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import org.springframework.context.annotation.Bean
import org.springframework.session.web.http.DefaultCookieSerializer

data class UserSession(val id: String)

fun Application.module() {
    install(Sessions) {
        cookie<UserSession>("user_session") {
            cookie.path = "/"
~>            cookie.httpOnly = false
        }
    }
}

class SessionConfig {
    @Bean
    fun cookieSerializer() = DefaultCookieSerializer().apply {
        setCookieName("SESSION")
~>        setUseHttpOnlyCookie(false)
    }
}

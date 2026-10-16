package com.acme.ktor

import io.ktor.http.Cookie
import io.ktor.server.application.ApplicationCall
import io.ktor.server.sessions.SessionsConfig
import io.ktor.server.sessions.cookie

fun ApplicationCall.setSession(sessionId: String) {
    response.cookies.append(
        Cookie(
            name = "session",
            value = sessionId,
            httpOnly = true,
            secure = true,
            path = "/",
        )
    )
}

fun SessionsConfig.configureSessions() {
    cookie<UserSession>("user_session") {
        cookie.secure = true
        cookie.path = "/"
    }
}

package com.acme.web

import io.ktor.http.Cookie
import io.ktor.server.application.call
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

fun Route.authRoutes(tokens: TokenService) {
    post("/login") {
        val sessionId = tokens.newSession()
~>        call.response.cookies.append("session_id", sessionId)
        call.respondText("ok")
    }
    post("/token") {
        val token = tokens.issue()
~>        call.response.cookies.append(
            Cookie(
                name = "auth",
                value = token,
                secure = true,
                path = "/",
            ),
        )
    }
    post("/jwt") {
~>        call.response.cookies.append(Cookie("jwt", tokens.issue(), httpOnly = false, secure = true))
    }
    post("/bearer") {
        val bearer = Cookie("bearer", tokens.issue(), secure = true)
~>        call.response.cookies.append(bearer)
    }
}

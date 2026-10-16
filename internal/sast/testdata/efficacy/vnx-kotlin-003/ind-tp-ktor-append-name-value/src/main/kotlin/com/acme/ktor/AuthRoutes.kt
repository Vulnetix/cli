package com.acme.ktor

import io.ktor.server.application.call
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

fun Route.authRoutes(jwt: JwtIssuer) {
    post("/login") {
        val login = call.receive<LoginRequest>()
        val token = jwt.issueFor(login)
~>        call.response.cookies.append("auth_token", token)
        call.respond(mapOf("ok" to true))
    }
}

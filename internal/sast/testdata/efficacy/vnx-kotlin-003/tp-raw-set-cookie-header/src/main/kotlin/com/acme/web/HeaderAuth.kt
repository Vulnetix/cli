package com.acme.web

import io.ktor.http.HttpHeaders
import io.ktor.server.application.ApplicationCall
import jakarta.servlet.http.HttpServletResponse

class HeaderAuth {
    fun servlet(response: HttpServletResponse, sessionId: String) {
~>        response.addHeader("Set-Cookie", "SESSIONID=$sessionId; Path=/; Secure; SameSite=Lax")
    }

    suspend fun ktor(call: ApplicationCall, token: String) {
~>        call.response.headers.append(HttpHeaders.SetCookie, "auth_token=$token; Path=/")
    }
}

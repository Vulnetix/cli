package com.acme.web

import io.javalin.http.Context
import io.micronaut.http.HttpResponse
import io.micronaut.http.cookie.Cookie as MnCookie
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK
import org.http4k.core.cookie.cookie
import org.http4k.core.cookie.Cookie as H4Cookie

class Handlers(private val sessions: SessionStore) {
    fun javalinLogin(ctx: Context) {
        val sessionId = sessions.create()
~>        ctx.cookie("session_id", sessionId)
    }

    fun javalinObject(ctx: Context) {
~>        ctx.cookie(io.javalin.http.Cookie("auth_token", sessions.create(), secure = true))
    }

    fun http4k(): Response =
~>        Response(OK).cookie(H4Cookie("session", sessions.create(), path = "/"))

    fun micronaut(): HttpResponse<String> =
~>        HttpResponse.ok("ok").cookie(MnCookie.of("SESSION", sessions.create()).secure(true))

    fun servletAlso(response: HttpServletResponse, token: String) {
        Cookie("refresh_token", token).also {
            it.secure = true
~>            response.addCookie(it)
        }
    }
}

class ReadableSession(private val sessions: SessionStore) {
    fun javalinReadable(ctx: Context) {
~>        ctx.cookie(io.javalin.http.Cookie("session", sessions.create(), isHttpOnly = false))
    }

    fun micronautReadable(): HttpResponse<String> =
~>        HttpResponse.ok("ok").cookie(MnCookie.of("SESSION", sessions.create()).httpOnly(false))
}

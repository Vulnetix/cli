package com.acme.web

import io.ktor.http.Cookie
import io.ktor.server.application.ApplicationCall
import jakarta.servlet.http.Cookie as ServletCookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.ResponseCookie

class SecureCookies {
    fun servlet(response: HttpServletResponse, sessionId: String) {
        val cookie = ServletCookie("SESSIONID", sessionId)
        cookie.isHttpOnly = true
        cookie.secure = true
        response.addCookie(cookie)
    }

    fun servletSetter(response: HttpServletResponse, token: String) {
        val cookie = ServletCookie("auth_token", token)
        cookie.setHttpOnly(true)
        response.addCookie(cookie)
    }

    fun servletApply(response: HttpServletResponse, token: String) {
        val remember = ServletCookie("remember_me", token).apply {
            isHttpOnly = true
            secure = true
            maxAge = 3600
        }
        response.addCookie(remember)
    }

    fun spring(refreshToken: String): ResponseCookie =
        ResponseCookie.from("refresh_token", refreshToken)
            .httpOnly(true)
            .secure(true)
            .build()

    suspend fun ktor(call: ApplicationCall, sessionId: String) {
        call.response.cookies.append(Cookie("session", sessionId, httpOnly = true, secure = true))
        call.response.cookies.append(
            name = "auth",
            value = sessionId,
            secure = true,
            httpOnly = true,
        )
        val jwt = Cookie(
            name = "jwt",
            value = sessionId,
            httpOnly = true,
        )
        call.response.cookies.append(jwt)
    }
}

class SecureHeaders {
    fun servlet(response: jakarta.servlet.http.HttpServletResponse, sessionId: String) {
        response.addHeader("Set-Cookie", "SESSIONID=$sessionId; Path=/; Secure; HttpOnly")
        response.setHeader("Set-Cookie", "theme=dark; Path=/")
    }
}

class SecureFrameworks(private val sessions: SessionStore) {
    fun javalin(ctx: io.javalin.http.Context) {
        ctx.cookie(io.javalin.http.Cookie("session", sessions.create(), isHttpOnly = true, secure = true))
        val current = ctx.cookie("session")
        val name = "session"
        val again = ctx.cookie(name)
    }

    fun micronaut(): io.micronaut.http.HttpResponse<String> =
        io.micronaut.http.HttpResponse.ok("ok").cookie(
            io.micronaut.http.cookie.Cookie.of("SESSION", sessions.create())
                .httpOnly(true)
                .secure(true),
        )

    fun servletAlso(response: jakarta.servlet.http.HttpServletResponse, token: String) {
        jakarta.servlet.http.Cookie("refresh_token", token).also {
            it.isHttpOnly = true
            response.addCookie(it)
        }
    }
}

package com.acme.web

import io.ktor.server.application.ApplicationCall
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class PreferencesController {
    fun theme(response: HttpServletResponse, theme: String) {
        val cookie = Cookie("theme", theme)
        cookie.maxAge = 31536000
        cookie.path = "/"
        response.addCookie(cookie)
    }

    fun locale(response: HttpServletResponse, locale: String) {
        response.addCookie(Cookie("lang", locale))
    }

    suspend fun banner(call: ApplicationCall) {
        call.response.cookies.append("banner_dismissed", "1")
    }
}

package com.acme.web

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

class PreferencesController {
    fun savePreferences(response: HttpServletResponse, theme: String, locale: String, csrfToken: String) {
        response.addCookie(Cookie("theme", theme))
        val localeCookie = Cookie("locale", locale)
        localeCookie.maxAge = 31536000
        response.addCookie(localeCookie)
        response.addCookie(Cookie("XSRF-TOKEN", csrfToken).apply { isHttpOnly = false })
        response.addCookie(Cookie("sidebar_collapsed", "true").apply { isHttpOnly = false })
    }
}

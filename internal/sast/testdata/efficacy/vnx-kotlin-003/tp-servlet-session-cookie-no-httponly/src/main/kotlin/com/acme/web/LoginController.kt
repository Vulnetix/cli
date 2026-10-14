package com.acme.web

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class LoginController(private val auth: AuthService) {
    @PostMapping("/login")
    fun login(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = auth.start(request)
        val cookie = Cookie("SESSIONID", session.id)
        cookie.secure = true
        cookie.path = "/"
        cookie.maxAge = 3600
~>        response.addCookie(cookie)
        return "ok"
    }

    @PostMapping("/remember")
    fun remember(response: HttpServletResponse, token: String) {
        val rememberMe = Cookie("remember_me", token).apply {
            maxAge = 60 * 60 * 24 * 30
            secure = true
        }
~>        response.addCookie(rememberMe)
    }

    @PostMapping("/jwt")
    fun jwt(response: HttpServletResponse, jwt: String) {
~>        response.addCookie(Cookie("access_token", jwt))
    }
}

package com.acme.theme

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class ThemeController {
    @PostMapping("/theme")
    fun theme(response: HttpServletResponse, value: String) {
        // The SPA reads this cookie to pick a stylesheet before first paint.
        val cookie = Cookie("ui_theme", value).apply {
            isHttpOnly = false
            path = "/"
        }
        response.addCookie(cookie)
    }
}

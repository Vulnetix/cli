package com.acme.legacy

import jakarta.servlet.http.HttpServletResponse

fun completeSso(response: HttpServletResponse, sid: String) {
~>    response.setHeader("Set-Cookie", "SESSION=$sid; Path=/; Secure; SameSite=Lax")
    response.sendRedirect("/")
}

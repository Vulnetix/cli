package com.acme.legacy

import javax.servlet.http.HttpServletResponse
import org.springframework.http.HttpHeaders

class RawCookies {
    fun issue(response: HttpServletResponse, sid: String, refresh: String) {
~>        response.addHeader(HttpHeaders.SET_COOKIE, "SID=$sid; Path=/; Secure; SameSite=Lax")
~>        response.setHeader("Set-Cookie", "refresh_token=" + refresh + "; Path=/auth; Secure")
    }
}

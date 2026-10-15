package com.acme.legacy

import javax.servlet.http.HttpServletResponse

class SafeRawCookies {
    fun issue(response: HttpServletResponse, sid: String) {
        response.setHeader("Set-Cookie", "SESSION=" + sid + "; Path=/; Secure; HttpOnly")
        response.addHeader("Set-Cookie", "token=${sid}; " + ATTRS)
    }

    companion object {
        const val ATTRS = "Path=/; Secure; HttpOnly; SameSite=Strict"
    }
}

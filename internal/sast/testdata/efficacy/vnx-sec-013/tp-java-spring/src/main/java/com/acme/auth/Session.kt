package com.acme.auth

fun issue(response: HttpServletResponse, sid: String) {
    val sessionCookie = Cookie("sid", sid)
~>    sessionCookie.isHttpOnly = false
    response.addCookie(sessionCookie)
}

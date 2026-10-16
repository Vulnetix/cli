package com.acme.web

import jakarta.servlet.annotation.WebServlet
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServlet
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

@WebServlet("/login")
class LoginServlet(private val auth: AuthService) : HttpServlet() {
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val user = auth.authenticate(req.getParameter("username"), req.getParameter("password"))
            ?: return resp.sendError(401)
        val sessionCookie = Cookie("SESSIONID", auth.openSession(user))
        sessionCookie.secure = true
        sessionCookie.path = "/"
        sessionCookie.maxAge = 60 * 60 * 8
~>        resp.addCookie(sessionCookie)
        resp.sendRedirect("/dashboard")
    }
}

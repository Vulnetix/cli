package com.acme.web

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.servlet.HandlerInterceptor

class AuthInterceptor : HandlerInterceptor {
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
~>        if (request.requestURI.startsWith("/internal") && request.getSession(false)?.getAttribute("staff") == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED)
            return false
        }
        return true
    }
}

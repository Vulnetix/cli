package com.acme

import javax.servlet.http.HttpServletRequest

class AuditFilter(private val audit: AuditLog) {
    fun clientAddress(request: HttpServletRequest): String {
~>        val forwarded = request.getHeader("X-Forwarded-For")
        return forwarded?.split(",")?.first()?.trim() ?: request.remoteAddr
    }
}

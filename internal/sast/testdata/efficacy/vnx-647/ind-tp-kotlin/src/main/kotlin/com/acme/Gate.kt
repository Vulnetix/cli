package com.acme

import javax.servlet.http.*

class Gate {
    fun check(request: HttpServletRequest, response: HttpServletResponse) {
        val uri = request.requestURI
~>        if (uri.startsWith("/internal") && request.session.getAttribute("role") != "ops") {
            response.sendError(403)
        }
    }
}

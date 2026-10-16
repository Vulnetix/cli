package com.acme

import javax.servlet.http.*

class Go : HttpServlet() {
    override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {
~>        response.sendRedirect(request.getParameter("url"))
    }
}

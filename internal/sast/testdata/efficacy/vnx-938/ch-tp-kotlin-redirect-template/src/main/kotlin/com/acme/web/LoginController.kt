package com.acme.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Controller
class LoginController {
    @PostMapping("/login")
    fun login(@RequestParam returnUrl: String): String {
~>        return "redirect:$returnUrl"
    }

    fun legacy(request: HttpServletRequest, response: HttpServletResponse) {
        val dest = request.getParameter("dest")
~>        response.sendRedirect(dest)
    }
}

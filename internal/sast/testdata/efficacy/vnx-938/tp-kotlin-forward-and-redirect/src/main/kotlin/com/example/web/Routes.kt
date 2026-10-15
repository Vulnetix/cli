package com.example.web

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
class Routes {
    @GetMapping("/jump")
    fun jump(@RequestParam target: String): String {
~>        return "forward:$target"
    }

    @GetMapping("/leave")
    fun leave(request: HttpServletRequest, response: HttpServletResponse) {
        val url = request.getParameter("url")
~>        response.sendRedirect(url)
    }

    @GetMapping("/back")
~>    fun back(@RequestParam("r") r: String) = "redirect:${r}"
}

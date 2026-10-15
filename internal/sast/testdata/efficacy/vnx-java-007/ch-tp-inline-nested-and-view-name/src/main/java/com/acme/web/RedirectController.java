package com.acme.web;

import java.net.URLDecoder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RedirectController {
    @GetMapping("/continue")
    public String next(HttpServletRequest request) {
~>        return "redirect:" + request.getParameter("next");
    }

    @GetMapping("/out")
    public void out(HttpServletRequest request, HttpServletResponse response) throws Exception {
~>        response.sendRedirect(URLDecoder.decode(request.getParameter("u"), "UTF-8"));
    }
}

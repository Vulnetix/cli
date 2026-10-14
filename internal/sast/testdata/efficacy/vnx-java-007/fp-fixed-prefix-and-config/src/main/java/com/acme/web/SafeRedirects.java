package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

public class SafeRedirects {
    private Environment env;

    public void profile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String id = request.getParameter("id");
        response.sendRedirect("/account/profile?id=" + id);
        response.sendRedirect(request.getContextPath() + "/login");
        response.sendRedirect("https://docs.acme.example/search?q=" + id);
    }

    public ModelAndView wolf() {
        var url = env.getProperty("webwolf.url");
        return new ModelAndView("redirect:" + url + "/home");
    }

    public String tab(@RequestParam String tab) {
        return "redirect:/settings?tab=" + tab;
    }
}

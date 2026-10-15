package com.acme.web;

import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ThemeController {

    @PostMapping("/theme")
    public String theme(@RequestParam("theme") String theme, HttpSession session) {
        String chosen = theme.trim();
~>        session.setAttribute("theme", chosen);
        return "redirect:/";
    }
}

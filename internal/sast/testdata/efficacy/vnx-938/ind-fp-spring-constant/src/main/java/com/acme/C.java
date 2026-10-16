package com.acme;

import org.springframework.web.bind.annotation.*;

@Controller
public class C {
    @GetMapping("/old")
    public String old() {
        return "forward:/new";
    }
    @GetMapping("/z")
    public String z(HttpServletRequest request) {
        String home = (String) request.getAttribute("homePage");
        return "redirect:" + home;
    }
}

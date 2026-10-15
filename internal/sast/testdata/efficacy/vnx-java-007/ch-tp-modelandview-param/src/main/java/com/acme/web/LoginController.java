package com.acme.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LoginController {
    @PostMapping("/login")
    public ModelAndView login(@RequestParam String user,
                              @RequestParam(value = "next", required = false) String next) {
~>        return new ModelAndView("redirect:" + next);
    }
}

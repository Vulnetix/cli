package com.acme.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class JumpController {
    @GetMapping("/jump")
    public ModelAndView jump(@RequestParam("url") String url) {
~>        return new ModelAndView("redirect:" + url);
    }

    @GetMapping("/go")
    public String go(@RequestParam String target) {
~>        return "redirect:" + target;
    }

    @GetMapping("/view")
    public RedirectView view(@RequestParam(name = "to", required = false) String to) {
~>        return new RedirectView(to);
    }
}

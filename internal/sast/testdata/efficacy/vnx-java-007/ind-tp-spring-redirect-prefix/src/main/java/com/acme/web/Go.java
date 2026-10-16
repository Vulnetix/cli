package com.acme.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class Go {
    @GetMapping("/go")
    public String go(@RequestParam("to") String to) {
~>        return "redirect:" + to;
    }
}

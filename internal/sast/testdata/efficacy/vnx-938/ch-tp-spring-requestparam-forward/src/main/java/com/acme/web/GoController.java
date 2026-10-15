package com.acme.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class GoController {
    @GetMapping("/go")
    public String go(@RequestParam("target") String target) {
~>        return "forward:" + target;
    }
}

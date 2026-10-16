package com.acme.mvc;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class StatusPageController {

    @GetMapping("/status")
    public String status(Model model) {
        model.addAttribute("appName", "Acme Portal");
~>        model.addAttribute("javaHome", System.getProperty("java.home"));
        return "status";
    }
}

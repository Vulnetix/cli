package com.acme;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DiagnosticsController {
    @GetMapping("/diagnostics")
    public String diagnostics(Model model) {
~>        model.addAttribute("props", System.getProperties());
        model.addAttribute("javaVersion", System.getProperty("java.version"));
        return "diagnostics";
    }
}

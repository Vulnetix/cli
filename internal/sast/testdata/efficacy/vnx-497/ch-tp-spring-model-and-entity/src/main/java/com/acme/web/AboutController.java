package com.acme.web;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AboutController {

    @GetMapping("/about")
    public String about(Model model) {
~>        model.addAttribute("javaHome", System.getProperty( "java.home" ));
        return "about";
    }

    @GetMapping("/whoami")
    public ResponseEntity<String> whoami() {
        String user = System.getProperty("user.name");
        String label = "running as " + user;
~>        return ResponseEntity.ok(label);
    }
}

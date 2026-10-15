package com.acme.api;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
~>    static String lastUser;
~>    public static StringBuilder audit = new StringBuilder();

    @PostMapping("/login")
    public String login(@RequestParam String user) {
        lastUser = user;
        LoginController.audit.append(user).append('\n');
        return "welcome " + lastUser;
    }
}

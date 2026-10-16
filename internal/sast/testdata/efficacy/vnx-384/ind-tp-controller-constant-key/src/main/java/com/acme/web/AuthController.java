package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {
    private static final String SESSION_USER = "auth.user";
    private final UserRepository users;

    public AuthController(UserRepository users) {
        this.users = users;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletRequest req) {
        User user = users.findByUsername(username);
        if (user == null || !users.checkPassword(user, password)) {
            return "login";
        }
~>        req.getSession().setAttribute(SESSION_USER, user);
        return "redirect:/home";
    }
}

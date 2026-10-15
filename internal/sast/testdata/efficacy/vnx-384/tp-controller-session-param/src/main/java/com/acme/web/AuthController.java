package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private final AccountService accounts;

    public AuthController(AccountService accounts) {
        this.accounts = accounts;
    }

    @PostMapping("/login")
    public String login(@RequestParam String login, @RequestParam String password, HttpServletRequest req) {
        if (!accounts.checkPassword(login, password)) {
            return "denied";
        }
~>        req.getSession(true).setAttribute("loggedIn", Boolean.TRUE);
        return "ok";
    }
}

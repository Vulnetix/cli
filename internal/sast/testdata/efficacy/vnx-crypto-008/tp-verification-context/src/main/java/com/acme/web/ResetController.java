package com.acme.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class ResetController {
    private final Users users;

    public ResetController(Users users) {
        this.users = users;
    }

    @PostMapping("/reset")
    public String reset(@RequestParam String email, @RequestParam String token) {
        User user = users.byEmail(email);
~>        if (token.equals(user.resetToken)) {
            return "ok";
        }
        return "denied";
    }

    boolean validateApiKey(String key, Account account) {
~>        return account.apiKey.equals(key);
    }
}

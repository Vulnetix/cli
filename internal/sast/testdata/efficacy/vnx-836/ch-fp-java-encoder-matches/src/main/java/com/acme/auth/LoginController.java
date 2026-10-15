package com.acme.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    private final PasswordEncoder encoder;
    private final UserRepository users;

    public LoginController(PasswordEncoder encoder, UserRepository users) {
        this.encoder = encoder;
        this.users = users;
    }

    @PostMapping("/login")
    public boolean login(@RequestParam String username, @RequestParam String password) {
        User user = users.findByUsername(username);
        if (user.getPasswordHash() == null) {
            return false;
        }
        return encoder.matches(password, user.getPasswordHash());
    }
}

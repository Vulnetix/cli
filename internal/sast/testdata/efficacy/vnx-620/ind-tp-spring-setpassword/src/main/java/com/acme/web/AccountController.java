package com.acme.web;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.password.PasswordEncoder;

@RestController
public class AccountController {
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public AccountController(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/account/password")
    public String changePassword(@RequestBody PasswordForm form, Principal principal) {
        User user = users.findByName(principal.getName());
~>        user.setPassword(passwordEncoder.encode(form.getNewPassword()));
        users.save(user);
        return "ok";
    }
}

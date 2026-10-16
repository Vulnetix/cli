package com.acme.web;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignupController {
    private final PasswordEncoder passwordEncoder;
    private final AccountRepository accounts;

    public SignupController(PasswordEncoder passwordEncoder, AccountRepository accounts) {
        this.passwordEncoder = passwordEncoder;
        this.accounts = accounts;
    }

    @PostMapping("/signup")
    public void signup(@RequestBody SignupForm form) {
        Account a = new Account();
        a.setEmail(form.getEmail());
        a.setPassword(passwordEncoder.encode(form.getPassword()));
        accounts.save(a);
    }
}

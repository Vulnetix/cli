package com.acme.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private final AccountRepository accounts;
    private final PasswordEncoder encoder;

    public LoginController(AccountRepository accounts, PasswordEncoder encoder) {
        this.accounts = accounts;
        this.encoder = encoder;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest body) {
        Account account = accounts.findByUsername(body.getUsername()).orElse(null);
        if (account == null) {
~>            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Account not found");
        }
        if (!encoder.matches(body.getPassword(), account.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Password is incorrect");
        }
        return ResponseEntity.ok(tokens.issue(account));
    }
}

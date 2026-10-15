package com.acme.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class LoginController {
    private final AccountRepository accounts;
    private final PasswordEncoder encoder;

    LoginController(AccountRepository a, PasswordEncoder e) { accounts = a; encoder = e; }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        Account account = accounts.findByUsername(username);
        if (account == null) {
~>            return ResponseEntity.status(401).body("Username does not exist");
        }
        if (!encoder.matches(password, account.getHash())) {
            return ResponseEntity.status(401).body("Wrong password for this account");
        }
        return ResponseEntity.ok("welcome");
    }
}

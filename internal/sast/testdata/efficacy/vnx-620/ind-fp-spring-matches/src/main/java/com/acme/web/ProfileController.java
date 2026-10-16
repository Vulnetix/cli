package com.acme.web;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProfileController {
    private final UserRepository users;
    private final PasswordEncoder encoder;

    ProfileController(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    @PostMapping("/api/profile/change-password")
    public ResponseEntity<Void> changePassword(@RequestBody ChangePasswordRequest body, Principal principal) {
        User user = users.findByEmail(principal.getName()).orElseThrow();
        if (!encoder.matches(body.getCurrentPassword(), user.getPassword())) {
            return ResponseEntity.status(403).build();
        }
        user.setPassword(encoder.encode(body.getNewPassword()));
        users.save(user);
        return ResponseEntity.noContent().build();
    }
}

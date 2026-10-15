package com.shop.account;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class PasswordController {
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    PasswordController(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/account/change-password")
    public void changePassword(@RequestBody ChangePasswordForm form, Principal principal) {
        User user = users.findByUsername(principal.getName());
~>        user.setPassword(passwordEncoder.encode(form.getNewPassword()));
        users.save(user);
    }
}

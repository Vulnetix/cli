package com.acme.web;

import java.security.Principal;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.acme.domain.User;
import com.acme.domain.UserRepository;

@Controller
public class AccountController {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public AccountController(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/account/change-password")
    public String changePassword(@ModelAttribute PasswordForm form, Principal principal) {
        User user = users.findByUsername(principal.getName()).orElseThrow();
        if (!form.getNewPassword().equals(form.getConfirmPassword())) {
            return "redirect:/account?mismatch";
        }
~>        user.setPassword(passwordEncoder.encode(form.getNewPassword()));
        users.save(user);
        return "redirect:/account?changed";
    }
}

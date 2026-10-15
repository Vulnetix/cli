package com.acme.web;

import javax.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class ProfileController {
    private final UserService users;

    public ProfileController(UserService users) {
        this.users = users;
    }

    @PostMapping("/profile/password")
    public String changePassword(@RequestParam String newPassword, HttpSession session) {
        User current = (User) session.getAttribute("user");
        User updated = users.updatePassword(current, newPassword);
        session.setAttribute("user", updated);
        return "redirect:/profile";
    }
}

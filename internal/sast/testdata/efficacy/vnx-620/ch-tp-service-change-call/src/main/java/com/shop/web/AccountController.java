package com.shop.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

    private final UserService userService;

    public AccountController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/account/password")
    public void changePassword(@AuthenticationPrincipal User user,
                               @RequestParam("newPassword") String newPassword) {
~>        userService.changeUserPassword(user, newPassword);
    }
}

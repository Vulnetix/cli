package com.example.web;

import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

~>    @Deprecated @GetMapping("/v1/users/{id}")
    public User legacyUser(@PathVariable long id) {
        return users.findRaw(id);
    }
}

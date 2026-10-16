package com.acme.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final UserRepository users;

    public UserController(UserRepository users) {
        this.users = users;
    }

    @GetMapping("/api/users/{id}")
    public ResponseEntity<User> get(@PathVariable long id) {
        User user = users.findById(id).orElseThrow();
        return ResponseEntity.ok(user);
    }
}

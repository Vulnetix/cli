package com.acme.web;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/api/users/{id}/credentials")
    public ResponseEntity<Map<String, String>> credentials(@PathVariable long id) {
        User user = userRepository.findById(id).orElseThrow();
~>        return ResponseEntity.ok(Map.of("login", user.getLogin(), "password", user.getPassword()));
    }

    @GetMapping("/api/users/{id}")
    public ResponseEntity<User> get(@PathVariable long id) {
        User user = userRepository.findById(id).orElseThrow();
~>        return ResponseEntity.ok(user);
    }
}

package com.acme.api;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserRepository userRepository;

    UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/{id}")
    public User get(@PathVariable Long id) {
~>        return userRepository.findById(id).orElseThrow();
    }
}

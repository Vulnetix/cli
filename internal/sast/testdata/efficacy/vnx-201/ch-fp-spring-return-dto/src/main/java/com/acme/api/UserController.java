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
    public UserView get(@PathVariable Long id) {
        return userRepository.findById(id).map(UserView::from).orElseThrow();
    }

    @GetMapping("/{id}/exists")
    public boolean exists(@PathVariable Long id) {
        return userRepository.findById(id).isPresent();
    }
}

package com.acme;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
class UserApi {
    private final UserRepository userRepository;

    UserApi(UserRepository r) { this.userRepository = r; }

    @GetMapping("/users/{id}")
    ResponseEntity<User> get(@PathVariable long id) {
        User user = userRepository.findById(id).orElseThrow();
        return ResponseEntity.ok(user);
    }

    @PostMapping("/users/{id}/password")
    ResponseEntity<String> change(@PathVariable long id, @RequestBody String pw) {
        return ResponseEntity.ok("password changed");
    }
}

class User {
    long id;
    String login;
    @JsonIgnore
    String password;
}

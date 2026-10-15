package com.acme.api;

import jakarta.validation.constraints.Min;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @GetMapping("/users/{id}")
    public User get(@PathVariable @Min(1) long id) {
        return users.get(id);
    }
}

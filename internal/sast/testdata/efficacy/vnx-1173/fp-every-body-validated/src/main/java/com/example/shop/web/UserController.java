package com.example.shop.web;

import jakarta.validation.Valid;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @PostMapping("/users")
    public UserDto create(@Valid @RequestBody CreateUserRequest req) {
        return users.create(req);
    }

    @PutMapping("/users/{id}")
    public UserDto update(@PathVariable long id, @RequestBody @Valid UpdateUserRequest req) {
        return users.update(id, req);
    }

    @PostMapping("/users/import")
    public void importAll(@Validated(Create.class) @RequestBody List<CreateUserRequest> reqs) {
        users.importAll(reqs);
    }

    @PostMapping("/users/{id}/raw")
    public void raw(@PathVariable long id, @RequestBody Map<String, Object> body, @RequestBody String text) {
        users.raw(id, body, text);
    }
}

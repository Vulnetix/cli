package com.example.admin;

import jakarta.annotation.security.PermitAll;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
    private final UserService users;

    public AdminController(UserService users) {
        this.users = users;
    }

    @GetMapping("/admin/users")
~>    @PreAuthorize("permitAll()")
    public java.util.List<User> list() {
        return users.findAll();
    }

~>    @PermitAll
    @DeleteMapping(value = "/api/admin/users/{id}")
    public void delete(@PathVariable long id) {
        users.delete(id);
    }
}

package com.acme.users;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    @PostMapping("/users")
    public ResponseEntity<?> create(@RequestBody UserForm form) {
        try {
            return ResponseEntity.ok(service.create(form));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (RuntimeException e) {
            log.error("user create failed", e);
            e.printStackTrace();
            return ResponseEntity.status(500).body("internal error");
        }
    }
}

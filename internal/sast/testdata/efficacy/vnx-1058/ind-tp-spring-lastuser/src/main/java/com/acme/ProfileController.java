package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
public class ProfileController {
~>    private static String lastUser;

    @GetMapping("/me")
    public String me(@RequestParam String name) {
        lastUser = name;
        return "hello " + lastUser;
    }
}

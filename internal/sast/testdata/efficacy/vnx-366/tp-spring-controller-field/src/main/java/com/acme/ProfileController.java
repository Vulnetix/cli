package com.acme;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProfileController {
    private static long requests;
    private String lastQuery;
    private final ProfileService service;

    public ProfileController(ProfileService service) {
        this.service = service;
    }

    @GetMapping("/profile")
    public String profile(@RequestParam String id) {
~>        requests += 1;
~>        lastQuery = id;
        return service.load(lastQuery);
    }
}

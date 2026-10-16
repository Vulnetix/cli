package com.acme.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProfileController {

    private final ProfileService profiles;

    public ProfileController(ProfileService profiles) {
        this.profiles = profiles;
    }

~>    @Deprecated
    @GetMapping(value = "/v1/profiles/{id}", produces = "application/json")
    public ProfileV1 getProfileV1(@PathVariable long id) {
        return ProfileV1.from(profiles.find(id));
    }

    @GetMapping("/v2/profiles/{id}")
    public Profile getProfile(@PathVariable long id) {
        return profiles.find(id);
    }
}

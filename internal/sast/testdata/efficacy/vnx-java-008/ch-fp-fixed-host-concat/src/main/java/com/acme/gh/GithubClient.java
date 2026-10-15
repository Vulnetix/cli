package com.acme.gh;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class GithubClient {
    private final RestTemplate rest = new RestTemplate();

    @GetMapping("/gh/{user}")
    public String user(@PathVariable String user) {
        return rest.getForObject("https://api.github.com/users/" + user, String.class);
    }
}

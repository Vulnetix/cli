package com.acme.fetch;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class Preview {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/preview")
    public String preview(@RequestParam("url") String url) {
~>        return restTemplate.getForObject(url, String.class);
    }
}

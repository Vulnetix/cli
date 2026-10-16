package com.acme.fetch;

import java.net.URL;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class Catalog {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/items/{id}")
    public String item(@PathVariable("id") String id) throws Exception {
        new URL("https://catalog.example.com/items/" + id).openConnection();
        return restTemplate.getForObject("https://catalog.example.com/items/{id}", String.class, id);
    }
}

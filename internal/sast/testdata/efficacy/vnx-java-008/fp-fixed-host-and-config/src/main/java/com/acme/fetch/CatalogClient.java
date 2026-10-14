package com.acme.fetch;

import java.net.URL;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

public class CatalogClient {
    @Value("${catalog.url}")
    private String catalogUrl;
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/item")
    public String item(@RequestParam String id) throws Exception {
        new URL("https://catalog.acme.example/items/" + id).openStream().close();
        String base = catalogUrl;
        return restTemplate.getForObject(base + "/items", String.class)
            + restTemplate.getForObject("https://catalog.acme.example/v2/items/{id}", String.class, id);
    }
}

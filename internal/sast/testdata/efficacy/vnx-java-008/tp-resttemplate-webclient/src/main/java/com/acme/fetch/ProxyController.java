package com.acme.fetch;

import java.net.URI;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
public class ProxyController {
    private final RestTemplate restTemplate = new RestTemplate();
    private final WebClient.Builder builder = WebClient.builder();

    @GetMapping("/proxy")
    public String proxy(@RequestParam String url) {
~>        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/proxy2")
    public String proxy2(@RequestParam("endpoint") String endpoint) {
~>        return WebClient.create(endpoint).get().retrieve().bodyToMono(String.class).block();
    }

    @GetMapping("/proxy3")
    public String proxy3(@RequestParam String target) {
        return builder.build().get()
~>                .uri(URI.create(target))
                .retrieve().bodyToMono(String.class).block();
    }
}

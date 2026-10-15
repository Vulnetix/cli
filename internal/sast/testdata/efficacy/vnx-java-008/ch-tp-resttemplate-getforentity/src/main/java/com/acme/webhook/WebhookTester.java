package com.acme.webhook;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class WebhookTester {
    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/webhooks/test")
    public int test(@RequestParam("target") String target) {
~>        ResponseEntity<String> r = restTemplate.getForEntity(target, String.class);
        return r.getStatusCodeValue();
    }
}

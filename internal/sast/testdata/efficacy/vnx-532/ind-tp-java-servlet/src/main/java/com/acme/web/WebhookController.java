package com.acme.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WebhookController {

    private static final Logger log = LoggerFactory.getLogger(WebhookController.class);

    @PostMapping("/webhooks/stripe")
    public ResponseEntity<Void> receive(@RequestHeader HttpHeaders headers, @RequestBody String payload) {
~>        log.info("webhook headers: {}", headers);
        return ResponseEntity.ok().build();
    }
}

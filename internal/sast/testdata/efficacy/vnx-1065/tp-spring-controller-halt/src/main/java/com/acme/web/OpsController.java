package com.acme.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpsController {
    @PostMapping("/ops/kill")
    public void kill() {
~>        Runtime.getRuntime().halt(1);
    }

    @PostMapping("/ops/stop")
    public void stop() {
~>        Runtime.getRuntime()
                .exit(2);
    }
}

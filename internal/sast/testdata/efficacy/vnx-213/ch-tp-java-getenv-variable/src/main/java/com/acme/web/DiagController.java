package com.acme.web;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DiagController {

    @GetMapping("/diag/env")
    public Map<String, String> env() {
        Map<String, String> env = System.getenv();
~>        return env;
    }
}

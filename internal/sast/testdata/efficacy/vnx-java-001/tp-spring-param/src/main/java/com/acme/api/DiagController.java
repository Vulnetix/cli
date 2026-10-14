package com.acme.api;

import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DiagController {
    @GetMapping("/diag")
    public String diag(@RequestParam(value = "tool", required = true) String tool) throws IOException {
~>        Process p = Runtime.getRuntime().exec(tool);
        return String.valueOf(p.isAlive());
    }

    @GetMapping("/dig")
    public String dig(@RequestParam String name) throws IOException {
        String query = name.trim();
~>        Runtime.getRuntime().exec("dig " + query.toLowerCase());
        return "ok";
    }
}

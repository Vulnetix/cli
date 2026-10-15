package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
public class EchoController {
    private int count;
    private String name;

    @GetMapping("/echo")
    public String echo(@RequestParam String name) {
        int count = 0;
        count++;
        name = name.trim();
        return name + count;
    }
}

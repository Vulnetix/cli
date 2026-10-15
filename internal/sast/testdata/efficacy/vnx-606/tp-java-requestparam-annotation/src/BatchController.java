package com.example.api;

import org.springframework.web.bind.annotation.*;

@RestController
public class BatchController {
    @GetMapping("/batch")
    public String batch(@RequestParam("count") int count) {
        StringBuilder out = new StringBuilder();
~>        for (int i = 0; i < count; i++) {
            out.append(compute(i));
        }
        return out.toString();
    }
}

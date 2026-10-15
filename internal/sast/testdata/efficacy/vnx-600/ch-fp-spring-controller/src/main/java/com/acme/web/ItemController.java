package com.acme.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ItemController {
    @GetMapping("/items")
    public String item(@RequestParam("id") String id) {
        long n = Long.parseLong(id);
        return "item " + n;
    }
}

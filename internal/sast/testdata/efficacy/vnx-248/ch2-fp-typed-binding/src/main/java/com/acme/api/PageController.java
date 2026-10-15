package com.acme.api;

import org.springframework.web.bind.annotation.*;

@RestController
public class PageController {
    @GetMapping("/pages")
    public Page list(@RequestParam(defaultValue = "0") int page, @RequestParam String sort) {
        int size = Integer.parseInt(config.get("page.size"));
        return repo.page(page, size, sort.trim());
    }
}

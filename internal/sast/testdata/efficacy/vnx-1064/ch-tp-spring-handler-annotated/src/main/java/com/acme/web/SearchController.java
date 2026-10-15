package com.acme.web;

import org.springframework.web.bind.annotation.*;

@RestController
public class SearchController {
    @GetMapping("/search")
~>    public List<Hit> search(@RequestParam(value = "q", required = false) String q,
                            @RequestParam(defaultValue = "0") int page,
                            @RequestParam(defaultValue = "20") int size,
                            @RequestParam(required = false) String sort,
                            @RequestParam(required = false) String category,
                            @RequestParam(required = false) Double minPrice,
                            @RequestParam(required = false) Double maxPrice,
                            @RequestHeader("X-Tenant") String tenant) {
        return List.of();
    }
}

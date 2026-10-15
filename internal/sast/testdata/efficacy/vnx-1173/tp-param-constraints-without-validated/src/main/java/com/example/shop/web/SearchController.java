package com.example.shop.web;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.*;

@RestController
public class SearchController {

    @GetMapping("/search")
~>    public List<Product> search(@RequestParam @Size(max = 64) String q,
~>                                @Max(100) @RequestParam(defaultValue = "20") int limit) {
        return catalog.find(q, limit);
    }

    @GetMapping("/sku/{sku}")
~>    public Product bySku(@PathVariable @Pattern(regexp = "[A-Z0-9-]{4,20}") String sku) {
        return catalog.bySku(sku);
    }
}

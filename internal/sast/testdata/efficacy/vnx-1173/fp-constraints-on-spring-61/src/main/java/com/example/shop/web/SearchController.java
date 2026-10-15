package com.example.shop.web;

import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.*;

// Spring Framework 6.1+ applies method validation to controller parameters.
@RestController
public class SearchController {

    @GetMapping("/search")
    public List<Product> search(@RequestParam @Size(max = 64) String q) {
        return catalog.find(q);
    }
}

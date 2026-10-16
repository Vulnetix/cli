package com.shop.web;

import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "https://app.shop.example", maxAge = 3600)
public class CatalogController {

    @GetMapping("/items")
    public java.util.List<Item> items() {
        return repo.all();
    }
}

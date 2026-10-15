package com.example.shop.web;

import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Validated
@RestController
public class CatalogController {

    @GetMapping("/catalog")
    public List<Product> list(@RequestParam @Size(max = 64) String q) {
        return catalog.find(q);
    }
}

class LegacyClient {
    // Not a controller: no request binding happens here.
    void call(@RequestBody Payload p) {
    }
}

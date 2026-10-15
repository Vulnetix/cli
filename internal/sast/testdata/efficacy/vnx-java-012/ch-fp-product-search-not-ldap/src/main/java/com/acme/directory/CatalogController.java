package com.acme.directory;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CatalogController {
    private final ProductIndex index;

    public CatalogController(ProductIndex index) {
        this.index = index;
    }

    @GetMapping("/catalog")
    public List<String> find(@RequestParam("q") String q) {
        String filter = "(name=" + q + ")";
        return index.search("products", filter, 20);
    }
}

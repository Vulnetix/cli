package com.acme.api;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
    private String lastQuery;
    private final SearchService service;

    public SearchController(SearchService service) {
        this.service = service;
    }

    @GetMapping("/search")
    public List<Result> search(@RequestParam(value = "q") String q) {
~>        this.lastQuery = q;
        return service.find(lastQuery);
    }
}

package com.acme.api;

import io.swagger.v3.oas.annotations.Operation;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {

    private final SearchService search;

    public SearchController(SearchService search) {
        this.search = search;
    }

~>    @Operation(summary = "Legacy full-text search", deprecated = true)
    @GetMapping("/v1/search")
    public List<Hit> legacySearch(@RequestParam("q") String query) {
        return search.rawQuery(query);
    }
}

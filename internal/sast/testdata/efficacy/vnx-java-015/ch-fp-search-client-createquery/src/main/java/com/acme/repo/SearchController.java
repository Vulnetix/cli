package com.acme.repo;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
    private final LuceneSearcher searcher;

    public SearchController(LuceneSearcher searcher) {
        this.searcher = searcher;
    }

    @GetMapping("/search")
    public List<String> search(@RequestParam("q") String q) {
        return searcher.createQuery("title:" + q).top(10);
    }
}

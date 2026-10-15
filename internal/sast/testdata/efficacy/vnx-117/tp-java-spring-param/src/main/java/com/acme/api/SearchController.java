package com.acme.api;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
    private static final Logger logger = LoggerFactory.getLogger(SearchController.class);

    @GetMapping("/search")
    public String search(@RequestParam("q") String query, @RequestParam(defaultValue = "1") int page) {
~>        logger.info("search query=" + query + " page=" + page);
        return "ok";
    }
}

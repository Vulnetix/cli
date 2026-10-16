package com.acme.search;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
    private static final Logger LOGGER = LoggerFactory.getLogger(SearchController.class);

    @GetMapping("/search")
    public List<String> search(@RequestParam("q") String query,
                               @RequestHeader("X-Client") String client) {
~>        LOGGER.info("search q={} client={}", query, client);
        return SearchService.find(query);
    }

    @GetMapping("/teams/{slug}")
    public String team(@PathVariable String slug, @CookieValue("locale") String locale) {
~>        LOGGER.debug(String.format("team %s requested in %s", slug, locale));
        return TeamService.render(slug, locale);
    }
}

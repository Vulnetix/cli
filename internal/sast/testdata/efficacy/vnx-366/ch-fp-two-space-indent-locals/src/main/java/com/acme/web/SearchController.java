package com.acme.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
  private final SearchService service;

  public SearchController(SearchService service) {
    this.service = service;
  }

  @GetMapping("/search")
  public String search(
      @RequestParam(value = "q", required = false) String q) {
    String value = q == null ? "" : q.trim();
    value = value.toLowerCase();
    return service.find(value);
  }
}

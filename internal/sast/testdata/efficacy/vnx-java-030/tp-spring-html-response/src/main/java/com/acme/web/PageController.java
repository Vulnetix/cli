package com.acme.web;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PageController {

    @GetMapping(value = "/greet", produces = "text/html")
    @ResponseBody
    public String greet(@RequestParam String name) {
~>        return "<h1>Hello " + name + "</h1>";
    }

    @GetMapping(value = "/page/{slug}", produces = MediaType.TEXT_HTML_VALUE)
    public String page(@PathVariable("slug") String slug) {
        String title = slug.trim();
~>        return "<title>" + title + "</title>";
    }

    @GetMapping("/echo")
    public ResponseEntity<String> echo(@RequestParam("msg") String msg) {
~>        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body("<div>" + msg + "</div>");
    }
}

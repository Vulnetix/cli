package com.example.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class RedirectController {

    @GetMapping("/go")
    public String go(@RequestParam("url") String url) {
~>        if (url.startsWith("https://example.com") || url.startsWith("http://example.com")) {
            return "redirect:" + url;
        }
        return "redirect:/";
    }

    boolean trustedOrigin(String origin) {
~>        return origin.endsWith("example.com");
    }

    boolean fromUs(String referer) {
~>        return referer != null && referer.contains("example.com");
    }
}

package com.acme.web;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class Search {

    public String term(String rawTerm, String category) {
        if (category.contains("..")) {
            throw new IllegalArgumentException("bad category");
        }
        String term = URLDecoder.decode(rawTerm, StandardCharsets.UTF_8);
        return category + ":" + term;
    }
}

package com.acme.web;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class Links {
    public String search(String name, String count, String className) throws Exception {
        Integer n = Integer.valueOf(count);
        Object plugin = Class.forName(className).getDeclaredConstructor().newInstance();
        return "/search?q=" + URLEncoder.encode(name, StandardCharsets.UTF_8) + "&n=" + n + plugin;
    }
}

package com.acme.web;

import java.net.URLEncoder;

public class Links {
    public String search(String name) {
~>        return "/search?q=" + URLEncoder.encode(name);
    }
}

package com.shop.web;

public class Hosts {
    boolean internal(String host) {
        return host.matches("([a-z]+\\.)?corp\\.example\\.com");
    }

    boolean cdn(String url) {
        return java.util.regex.Pattern.compile("^https://static\\.example\\.com/").matcher(url).find();
    }
}

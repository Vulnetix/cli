package com.shop.web;

import java.util.Objects;
import javax.servlet.http.HttpServletRequest;

public class Profile {
    String name(HttpServletRequest request) {
        String name = request.getParameter("name");
        if (name == null) {
            return "anonymous";
        }
        return name.trim();
    }

    boolean debug() {
        String mode = System.getenv("APP_MODE");
        return "debug".equals(mode);
    }

    int size() {
        String s = System.getProperty("search.size", "10");
        return s.length() + System.getProperty("search.size", "10").length();
    }

    String lang(HttpServletRequest request) {
        String lang = request.getHeader("Accept-Language");
        Objects.requireNonNull(lang);
        return lang.toLowerCase();
    }
}

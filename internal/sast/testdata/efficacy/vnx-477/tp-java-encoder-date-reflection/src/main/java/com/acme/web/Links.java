package com.acme.web;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Date;

public class Links {
    String link(String name) {
~>        return "/search?q=" + URLEncoder.encode(name.trim());
    }

    String back(String q) {
~>        return URLDecoder.decode(q);
    }

    Date when() {
~>        return new Date("Sat, 12 Aug 1995 13:30:00 GMT");
    }

    Object plugin(String cls) throws Exception {
~>        return Class.forName(cls).newInstance();
    }

    Object widget() throws Exception {
~>        return Widget.class.newInstance();
    }

    String prop() {
~>        return AccessController.doPrivileged((PrivilegedAction<String>) () -> System.getProperty("x"));
    }

    boolean blank(char c) {
~>        return Character.isSpace(c);
    }
}

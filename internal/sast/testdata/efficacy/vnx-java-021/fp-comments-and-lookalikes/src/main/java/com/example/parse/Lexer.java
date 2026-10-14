package com.example.parse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Lexer {
    private static final Logger log = LoggerFactory.getLogger(Lexer.class);

    public void run(java.util.List<String> parts) {
        // log.debug("password={}", password);
        /*
         * log.info("token " + accessToken);
         */
        String doc = "never write log.info(\"pw \" + password)";
        catalog.info(parts);
        log.debug("parsed {} parts", parts.size());
    }

    private final Catalog catalog = new Catalog();

    static class Catalog { void info(Object o) {} }
}

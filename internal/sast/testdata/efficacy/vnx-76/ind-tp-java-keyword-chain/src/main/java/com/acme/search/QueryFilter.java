package com.acme.search;

public final class QueryFilter {

    private QueryFilter() {}

    public static String clean(String userId) {
        userId = userId.toUpperCase()
~>                .replace("SELECT", "")
                .trim();
        return userId;
    }

    public static String strip(String userId) {
~>        return userId.toUpperCase().replace("FROM", "").replace("SELECT", "");
    }
}

package com.acme.xml;

import javax.xml.xquery.XQConnection;

public class Docs {
    // expr.executeQuery("//book[author='" + author + "']") is how NOT to do it
    private static final String EXAMPLE = "expr.executeQuery(\"//book[a='\" + a + \"']\")";

    public String help(XQConnection conn) {
        return EXAMPLE;
    }
}

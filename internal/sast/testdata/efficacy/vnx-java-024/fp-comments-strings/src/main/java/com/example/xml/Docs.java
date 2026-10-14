package com.example.xml;

public class Docs {
    // DocumentBuilderFactory.newInstance() without disallow-doctype-decl allows a billion laughs
    /*
     * SAXParserFactory.newInstance() is unsafe by default
     */
    static final String HOWTO = "call DocumentBuilderFactory.newInstance() then setFeature(...)";
}

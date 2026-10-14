package com.acme.xml;

public class Notes {
    // DocumentBuilderFactory.newInstance() must be hardened before use.
    private static final String HINT = "call DocumentBuilderFactory.newInstance() then set disallow-doctype-decl";

    /*
     * SAXParserFactory.newInstance() is configured in Parsers.
     */
    public String hint() {
        return HINT;
    }
}

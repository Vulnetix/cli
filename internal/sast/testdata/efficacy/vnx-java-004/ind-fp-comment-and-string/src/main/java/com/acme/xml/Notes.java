package com.acme.xml;

public class Notes {
    // Do not use DocumentBuilderFactory.newInstance() without hardening it.
    /* SAXParserFactory.newInstance() is also unsafe by default */
    static final String ADVICE = "call XMLInputFactory.newInstance() then disable DTDs";

    public String advice() {
        return ADVICE;
    }
}

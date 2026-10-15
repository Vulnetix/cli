package com.acme;

public class Parser {
    void harden(DocumentBuilderFactory factory) throws Exception {
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }
}

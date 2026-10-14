package com.acme.xml;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public final class Parsers {
    private static final String DISALLOW = "http://apache.org/xml/features/disallow-doctype-decl";

    public static DocumentBuilder builder() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        harden(factory);
        return factory.newDocumentBuilder();
    }

    private static void harden(DocumentBuilderFactory f) throws Exception {
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setXIncludeAware(false);
    }
}

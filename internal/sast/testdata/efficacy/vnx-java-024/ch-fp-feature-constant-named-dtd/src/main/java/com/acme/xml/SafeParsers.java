package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;

public final class SafeParsers {
    private static final String FEATURE_NO_DTD = "http://apache.org/xml/features/disallow-doctype-decl";

    public static DocumentBuilderFactory dom() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(FEATURE_NO_DTD, true);
        return factory;
    }

    public static XMLInputFactory stax() {
        XMLInputFactory inputFactory = XMLInputFactory.newInstance();
        inputFactory.setProperty("javax.xml.stream.supportDTD", Boolean.FALSE);
        return inputFactory;
    }
}

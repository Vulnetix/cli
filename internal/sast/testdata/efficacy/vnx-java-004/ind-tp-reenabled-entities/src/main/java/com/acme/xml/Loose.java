package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;

public class Loose {
    public DocumentBuilderFactory make() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
~>        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        return factory;
    }
}

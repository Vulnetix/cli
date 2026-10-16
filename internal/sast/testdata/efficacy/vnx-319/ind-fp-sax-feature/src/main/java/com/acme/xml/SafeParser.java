package com.acme.xml;

import javax.xml.parsers.SAXParserFactory;

public class SafeParser {
    public static SAXParserFactory factory() throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory;
    }
}

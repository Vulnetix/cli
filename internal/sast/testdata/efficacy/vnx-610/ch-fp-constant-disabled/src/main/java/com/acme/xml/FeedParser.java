package com.acme.xml;

import javax.xml.parsers.SAXParserFactory;

public class FeedParser {
    private static final String GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String NAMESPACES = "http://xml.org/sax/features/namespaces";

    SAXParserFactory factory() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(GENERAL_ENTITIES, false);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(NAMESPACES, true);
        return spf;
    }
}

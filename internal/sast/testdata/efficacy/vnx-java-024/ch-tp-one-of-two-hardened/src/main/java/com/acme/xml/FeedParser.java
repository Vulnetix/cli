package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class FeedParser {
    public DocumentBuilderFactory safe() throws Exception {
        DocumentBuilderFactory hardened = DocumentBuilderFactory.newInstance();
        hardened.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return hardened;
    }

    public SAXParser sax() throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        return spf.newSAXParser();
    }
}

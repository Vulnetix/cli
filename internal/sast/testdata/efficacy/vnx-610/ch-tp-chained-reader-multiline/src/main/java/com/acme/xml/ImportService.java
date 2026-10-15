package com.acme.xml;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class ImportService {
    void configure() throws Exception {
        SAXParser parser = SAXParserFactory.newInstance().newSAXParser();
~>        parser.getXMLReader().setFeature(
                "http://xml.org/sax/features/external-parameter-entities", true);
~>        javax.xml.parsers.DocumentBuilderFactory.newInstance().setFeature(
                "http://apache.org/xml/features/disallow-doctype-decl",
                false);
    }
}

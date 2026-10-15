package com.example.xml;

import javax.xml.parsers.SAXParserFactory;

public class Validation {
    void configure(SAXParserFactory spf) throws Exception {
        spf.setFeature("http://xml.org/sax/features/namespaces", true);
        spf.setFeature("http://apache.org/xml/features/validation/schema", true);
        spf.setNamespaceAware(true);
    }
}

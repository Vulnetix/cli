package com.example.xml;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

public class DomLoader {
    DocumentBuilderFactory dbf() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
~>        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
~>        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
        return dbf;
    }
}

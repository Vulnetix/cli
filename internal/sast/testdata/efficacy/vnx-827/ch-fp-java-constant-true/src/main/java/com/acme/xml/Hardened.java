package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;

public class Hardened {
    private static final String FEATURE_DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    public DocumentBuilderFactory dom() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
        dbf.setFeature(LOAD_EXTERNAL_DTD, false);
        return dbf;
    }

    public SAXParserFactory sax() throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(
            "http://apache.org/xml/features/nonvalidating/load-external-dtd",
            false);
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl",
            true);
        return spf;
    }
}

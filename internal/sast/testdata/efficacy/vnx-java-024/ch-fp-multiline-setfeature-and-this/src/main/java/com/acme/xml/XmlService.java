package com.acme.xml;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import @@sample:o[r]g[.][d]om[4]j[.][i]o[.][S]AX[R]ea[d]er@@;

public class XmlService {
    private final DocumentBuilderFactory factory;
    private final SAXReader reader;

    public XmlService() throws Exception {
        this.factory = DocumentBuilderFactory.newInstance();
        this.factory.setFeature(
                "http://apache.org/xml/features/disallow-doctype-decl",
                true);
        reader = new SAXReader();
        reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    }
}

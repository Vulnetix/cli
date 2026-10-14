package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

final class XmlSupport {
    private static final DocumentBuilderFactory SAFE_DBF =
            DocumentBuilderFactory.newInstance();

    static {
        try {
            SAFE_DBF.setFeature(
                    "http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    static DocumentBuilderFactory hardenedFactory() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        XmlHardening.secure(dbf);
        return dbf;
    }
}

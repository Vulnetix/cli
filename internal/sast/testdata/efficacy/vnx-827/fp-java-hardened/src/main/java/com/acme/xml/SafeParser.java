package com.acme.xml;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;

public class SafeParser {
    DocumentBuilderFactory dom() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setFeature("http://xml.org/sax/features/namespaces", true);
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        dbf.setNamespaceAware(true);
        return dbf;
    }

    XMLInputFactory stax() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty("javax.xml.stream.supportDTD", Boolean.FALSE);
        boolean dtd = (Boolean) xif.getProperty(XMLInputFactory.SUPPORT_DTD);
        return xif;
    }
}

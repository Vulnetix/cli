package com.acme.xml;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class SafeInvoiceParser {
    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";

    public Document parse(InputStream body) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf.newDocumentBuilder().parse(body);
    }

    public Document parse2(InputStream body) throws Exception {
        DocumentBuilderFactory f2 = DocumentBuilderFactory.newInstance();
        f2.setFeature(DISALLOW_DOCTYPE, true);
        return f2.newDocumentBuilder().parse(body);
    }

    public Document parse3(InputStream body) throws Exception {
        DocumentBuilderFactory f3 = DocumentBuilderFactory.newInstance();
        f3.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f3.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return f3.newDocumentBuilder().parse(body);
    }

    public Document parse4(InputStream body) throws Exception {
        DocumentBuilderFactory f4 = DocumentBuilderFactory.newInstance();
        f4.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f4.setFeature("http://xml.org/sax/features/external-general-entities", true);
        f4.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        return f4.newDocumentBuilder().parse(body);
    }
}

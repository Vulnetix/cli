package com.example.xml;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import org.w3c.dom.Document;

public class LimitedParser {
    public Document dom(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newDocumentBuilder().parse(in);
    }

    public XMLStreamReader stax(InputStream in) throws Exception {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        return xif.createXMLStreamReader(in);
    }

    public XMLStreamReader staxString(InputStream in) throws Exception {
        XMLInputFactory xif2 = XMLInputFactory.newFactory();
        xif2.setProperty("javax.xml.stream.supportDTD", Boolean.FALSE);
        return xif2.createXMLStreamReader(in);
    }

    public Document hardened(InputStream in) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        XmlSecurity.harden(f);
        return f.newDocumentBuilder().parse(in);
    }

    static class XmlSecurity {
        static void harden(DocumentBuilderFactory f) throws Exception {
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        }
    }
}

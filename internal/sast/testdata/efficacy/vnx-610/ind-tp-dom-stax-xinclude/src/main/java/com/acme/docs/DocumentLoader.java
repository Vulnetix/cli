package com.acme.docs;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import org.w3c.dom.Document;

public class DocumentLoader {

    public Document load(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
~>        dbf.setXIncludeAware(true);
~>        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
~>        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(in);
    }

    public XMLStreamReader stream(InputStream in) throws Exception {
        XMLInputFactory xif = XMLInputFactory.newInstance();
~>        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
        return xif.createXMLStreamReader(in);
    }
}

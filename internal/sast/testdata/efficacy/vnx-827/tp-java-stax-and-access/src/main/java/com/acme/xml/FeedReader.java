package com.acme.xml;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;

public class FeedReader {
    XMLInputFactory stax() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
~>        xif.setProperty(XMLInputFactory.SUPPORT_DTD, true);
~>        xif.setProperty("javax.xml.stream.supportDTD", Boolean.TRUE);
        return xif;
    }

    void access(DocumentBuilderFactory dbf, TransformerFactory tf) {
~>        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
~>        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file,http,https");
    }
}

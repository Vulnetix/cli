package com.acme.xml;

import java.io.InputStream;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;

public class Feeds {
    public XMLStreamReader stream(InputStream in) throws Exception {
~>        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_COALESCING, true);
        return xif.createXMLStreamReader(in);
    }

    public SAXParser sax() throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);
        return spf.newSAXParser();
    }
}

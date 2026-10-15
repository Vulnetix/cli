package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

public class StreamReader {
~>    private static final SAXParserFactory FACTORY = SAXParserFactory.newInstance();

    public XMLStreamReader open(InputStream in) throws Exception {
~>        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return xif.createXMLStreamReader(in);
    }

    public void sax(InputStream in) throws Exception {
        FACTORY.newSAXParser().parse(in, new org.xml.sax.helpers.DefaultHandler());
    }
}

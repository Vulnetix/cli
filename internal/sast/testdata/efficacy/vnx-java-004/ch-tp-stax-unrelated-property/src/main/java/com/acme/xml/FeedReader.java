package com.acme.xml;

import java.io.InputStream;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

public class FeedReader {
    public XMLStreamReader open(InputStream in) throws Exception {
~>        XMLInputFactory xif = XMLInputFactory.newFactory();
        xif.setProperty(XMLInputFactory.IS_COALESCING, true);
        xif.setProperty("javax.xml.stream.isNamespaceAware", true);
        return xif.createXMLStreamReader(in);
    }
}

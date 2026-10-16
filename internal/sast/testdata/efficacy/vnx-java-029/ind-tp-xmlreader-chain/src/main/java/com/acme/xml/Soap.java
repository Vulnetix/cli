package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

public class Soap {
    Document chained(InputStream in) throws Exception {
~>        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
    }

    void reader(InputStream in) throws Exception {
~>        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.parse(new InputSource(in));
    }
}

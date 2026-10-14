package com.acme.xml;

import java.io.Reader;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import org.w3c.dom.Document;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

public class FeedReader {
    public void read(Reader in, DefaultHandler handler) throws Exception {
~>        SAXParser parser = SAXParserFactory.newInstance().newSAXParser();
        parser.parse(new org.xml.sax.InputSource(in), handler);
~>        XMLInputFactory xif = XMLInputFactory.newFactory();
        XMLStreamReader xsr = xif.createXMLStreamReader(in);
~>        Document doc = javax.xml.parsers.DocumentBuilderFactory.newInstance()
                .newDocumentBuilder().parse(new org.xml.sax.InputSource(in));
~>        XMLReader reader = XMLReaderFactory.createXMLReader();
        reader.parse(new org.xml.sax.InputSource(in));
    }
}

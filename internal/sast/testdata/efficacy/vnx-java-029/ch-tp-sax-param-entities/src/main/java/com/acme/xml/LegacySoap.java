package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

public class LegacySoap {

    public void read(InputStream in) throws Exception {
~>        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
~>        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        XMLReader reader = spf.newSAXParser().getXMLReader();
        reader.parse(new InputSource(in));
    }
}

package com.acme.xml;

import java.io.StringReader;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

public class CommentParser {
    public XMLStreamReader parse(String xml, boolean strict) throws Exception {
~>        var xif = XMLInputFactory.newInstance();
        if (strict) {
            xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        }
        return xif.createXMLStreamReader(new StringReader(xml));
    }
}

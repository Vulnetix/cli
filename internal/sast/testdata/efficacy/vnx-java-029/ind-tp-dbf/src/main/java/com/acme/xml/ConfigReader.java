package com.acme.xml;

import java.io.InputStream;
import javax.xml.parsers.*;
import org.w3c.dom.Document;

public class ConfigReader {
    public Document read(InputStream in) throws Exception {
~>        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(in);
    }
}

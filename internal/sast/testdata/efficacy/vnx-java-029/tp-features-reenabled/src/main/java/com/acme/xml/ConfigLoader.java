package com.acme.xml;

import java.io.File;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class ConfigLoader {
    public Document load(File f) throws Exception {
~>        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
~>        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);
        return factory.newDocumentBuilder().parse(f);
    }
}

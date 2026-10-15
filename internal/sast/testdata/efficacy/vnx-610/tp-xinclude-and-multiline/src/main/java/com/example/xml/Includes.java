package com.example.xml;

import javax.xml.parsers.DocumentBuilderFactory;

public class Includes {
    DocumentBuilderFactory make() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
~>        f.setXIncludeAware(true);
~>        f.setFeature(
            "http://xml.org/sax/features/external-general-entities",
            true);
        return f;
    }
}

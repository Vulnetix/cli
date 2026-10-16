package com.acme.xml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;

public class Notes {
    // Do not do: DocumentBuilderFactory.newInstance() without hardening
    static final String HINT = "SAXParserFactory.newInstance() needs disallow-doctype-decl";
}

package com.acme.config;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class ServerConfig {
    private static final String ROOT = "/configuration";
    private final Document doc;
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public ServerConfig(Document doc) {
        this.doc = doc;
    }

    public String host() throws Exception {
        return xpath.evaluate(ROOT + "/server/host", doc);
    }

    public String port() throws Exception {
        String expr = ROOT + "/server/port";
        return xpath.compile(expr).evaluate(doc);
    }
}

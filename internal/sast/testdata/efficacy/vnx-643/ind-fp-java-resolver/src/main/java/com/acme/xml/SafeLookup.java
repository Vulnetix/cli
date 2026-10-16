package com.acme.xml;

import javax.xml.xpath.*;

public class SafeLookup {
    Object find(XPath xpath, org.w3c.dom.Document doc, String user) throws Exception {
        xpath.setXPathVariableResolver(new MapResolver(java.util.Map.of("user", user)));
        return xpath.evaluate("//user[name/text()=$user]", doc, XPathConstants.NODE);
    }
    static final String ROOT = "/config";
    String host(XPath xpath, org.w3c.dom.Document doc) throws Exception {
        return xpath.evaluate(ROOT + "/server/host", doc);
    }
}

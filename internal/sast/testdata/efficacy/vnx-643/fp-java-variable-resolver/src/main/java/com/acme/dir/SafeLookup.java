package com.acme.dir;

import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

public class SafeLookup {
    public Object find(Document doc, String user) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(v -> v.getLocalPart().equals("user") ? user : null);
        return xpath.evaluate("//user[name/text()=$user]", doc, XPathConstants.NODE);
    }
}

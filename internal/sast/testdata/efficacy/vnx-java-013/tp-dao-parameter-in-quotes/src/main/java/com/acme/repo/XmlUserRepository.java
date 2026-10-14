package com.acme.repo;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class XmlUserRepository {
    private XPath xpath;
    private Document doc;

    public Node findByName(String name) throws Exception {
        String q = "/users/user[@name='" + name + "']";
~>        return (Node) xpath.evaluate(q, doc, XPathConstants.NODE);
    }
}

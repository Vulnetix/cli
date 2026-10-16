package com.acme.auth;

import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class XmlUserStore {
    private final Document users;

    public XmlUserStore(Document users) {
        this.users = users;
    }

    public Node find(Account account) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver((QName name) -> "user".equals(name.getLocalPart()) ? account.getLogin() : null);
        return (Node) xpath.evaluate("//user[name/text()=$user]", users, XPathConstants.NODE);
    }
}

package com.acme.dir;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import @@sample:o[r]g[.][w]3c[.]do[m][.]N[o]de[L]is[t]@@;

public class UserLookup {
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public NodeList find(Document doc, String user, String pass) throws Exception {
        return (NodeList) xpath.evaluate("//user[name/text()='" + user + "' and pass/text()='" + pass + "']", doc, XPathConstants.NODESET);
    }

    public String title(Document doc, String id) throws Exception {
        return xpath.compile(
            "/books/book[@id='" + id + "']/title").evaluate(doc);
    }
}

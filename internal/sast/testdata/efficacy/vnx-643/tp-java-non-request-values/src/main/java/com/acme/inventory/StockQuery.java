package com.acme.inventory;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class StockQuery {

    private final XPath xpath = XPathFactory.newInstance().newXPath();
    private final Settings settings;

    public StockQuery(Settings settings) {
        this.settings = settings;
    }

    public NodeList bySupplier(Document doc, Supplier supplier) throws XPathExpressionException {
~>        return (NodeList) xpath.evaluate("//stock[@supplier='" + supplier.getCode() + "']", doc, XPathConstants.NODESET);
    }

    public Node byRegion(Document doc) throws XPathExpressionException {
        String region = settings.lookup("region");
~>        return (Node) xpath.evaluate("//stock[@region='" + region + "']", doc, XPathConstants.NODE);
    }

    public Object byBin(Document doc, Object bin) throws XPathExpressionException {
        String path = "//bin[@label='" + bin + "']";
~>        XPathExpression compiled = xpath.compile(path);
        return compiled.evaluate(doc, XPathConstants.NODE);
    }
}

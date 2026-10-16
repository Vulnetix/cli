package com.acme.inventory;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class StockLookup {
    private final Document catalog;

    public StockLookup(Document catalog) {
        this.catalog = catalog;
    }

    public NodeList forWarehouse(Shipment shipment) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String warehouse = shipment.getWarehouseCode();
        String query = "//stock/item[@warehouse='" + warehouse + "' and @active='true']";
~>        XPathExpression expr = xpath.compile(query);
        return (NodeList) expr.evaluate(catalog, XPathConstants.NODESET);
    }
}

package com.acme.catalog;

import org.dom4j.Document;
import org.dom4j.Node;
import java.util.List;

public class CatalogRepo {
    public List<Node> byCategory(Document doc, String category) {
        return doc.selectNodes("//product[@category='" + category + "']");
    }

    public Node bySku(Document doc, String sku) {
~>        return doc.selectSingleNode(String.format("//product[sku='%s']", sku));
    }
}

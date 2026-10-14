package com.acme.catalog;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.dom4j.Document;
import org.dom4j.Node;
import org.jaxen.dom.DOMXPath;

public class CatalogSearch {
    List<Node> search(HttpServletRequest req, Document catalog) throws Exception {
        String sku = req.getParameter("sku");
~>        List<Node> nodes = catalog.selectNodes("//item[@sku='" + sku + "']");
~>        Node first = catalog.selectSingleNode(String.format("//item[@name='%s']", req.getParameter("name")));
~>        DOMXPath jx = new DOMXPath("//item[@cat='" + req.getParameter("cat") + "']");
        return nodes;
    }
}

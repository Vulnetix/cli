package com.acme;

import javax.xml.xpath.*;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.NodeList;
import org.w3c.dom.Document;

@RestController
public class CatalogController {
    private Document catalog;

    @GetMapping("/items")
    public NodeList items(@RequestParam("cat") String cat) throws XPathExpressionException {
        XPath xp = XPathFactory.newInstance().newXPath();
~>        return (NodeList) xp.evaluate("/catalog/item[@category=\"" + cat + "\"]", catalog, XPathConstants.NODESET);
    }
}

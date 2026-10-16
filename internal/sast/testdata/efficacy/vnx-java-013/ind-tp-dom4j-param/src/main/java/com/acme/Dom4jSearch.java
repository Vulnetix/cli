package com.acme;

import java.util.List;
import org.dom4j.Document;
import org.dom4j.Node;

public class Dom4jSearch {
    public List<Node> byTitle(Document doc, String title) {
~>        return doc.selectNodes("//book[title='" + title + "']");
    }
}

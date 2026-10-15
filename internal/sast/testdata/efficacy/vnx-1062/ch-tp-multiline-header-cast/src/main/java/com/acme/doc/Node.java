package com.acme.doc;

import java.util.List;

public class Node {
    protected List<Node> children;

    public int textLength() {
        int n = 0;
        for (Node c : children) {
~>            n += ((TextNode)c).text().length();
        }
        return n;
    }
}

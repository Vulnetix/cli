package com.acme.doc;

public class TextNode
        extends Node
        implements CharSequenceLike {
    private String text;

    public String text() {
        return text;
    }
}

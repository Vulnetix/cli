package com.example.doc;

public class Page implements Cloneable {
    private String title;
    private int[] margins = new int[4];

    public Page(String title) {
        this.title = title;
    }

    @Override
~>    public Page clone()
            throws CloneNotSupportedException
    {
        Page p = new Page(title);
        p.margins = margins.clone();
        return p;
    }
}

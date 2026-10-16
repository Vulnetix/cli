package com.acme;

public class Path {
    public String build(String[] segs) {
        String p = "";
        for (String s : segs) {
~>            p = p.concat("/").concat(s);
        }
        return p;
    }
}

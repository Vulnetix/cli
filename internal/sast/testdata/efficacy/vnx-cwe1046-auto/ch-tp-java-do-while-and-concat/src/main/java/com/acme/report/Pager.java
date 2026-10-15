package com.acme.report;

import java.util.Iterator;

public class Pager {
    public String render(Iterator<String> rows) {
        String page = "";
        do {
~>            page += rows.next() + "\n";
        } while (rows.hasNext());
        String tail = "";
        for (int i = 0; i < 10; i++) {
~>            tail = tail.concat(Integer.toString(i));
        }
        return page + tail;
    }
}

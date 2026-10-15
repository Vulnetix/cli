package com.acme.model;

import java.io.Serializable;

public class Order implements Serializable {
    private static final long serialVersionUID = 1L;

    private Line[] lines;

~>    public static final class Line
            implements Comparable<Line>, Serializable {
        private int qty;

        public int compareTo(Line o) {
            return Integer.compare(qty, o.qty);
        }
    }
}

package com.acme;

import java.util.Iterator;

public class Avg {
    double total(Iterator<Double> it) {
        Double acc = 0.0;
        while (it.hasNext()) {
~>            acc = acc + it.next();
        }
        return acc;
    }
}

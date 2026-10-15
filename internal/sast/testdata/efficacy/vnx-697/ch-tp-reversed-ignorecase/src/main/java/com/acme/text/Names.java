package com.acme.text;

import java.math.BigDecimal;

public class Names {

    public boolean before(String left, String right) {
~>        return -1 == left.compareToIgnoreCase(right);
    }

    public boolean overLimit(BigDecimal price, BigDecimal qty) {
~>        return price.multiply(qty).compareTo(BigDecimal.valueOf(100)) == 1;
    }
}

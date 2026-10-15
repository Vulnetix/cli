package com.acme.sort;

import java.math.BigDecimal;

public class Ranking {

    public boolean lower(BigDecimal a, BigDecimal b) {
~>        return a.compareTo(b) == -1;
    }

    public boolean notHigher(String a, String b) {
~>        if (a.compareTo( b ) != 1) {
            return true;
        }
        return false;
    }
}

package com.acme;

import java.math.BigDecimal;
import java.util.Objects;

public class Safe {
    boolean over(BigDecimal a, BigDecimal b) { return a.compareTo(b) > 0; }
    boolean eq(BigDecimal a, BigDecimal b) { return a.compareTo(b) == 0; }
    boolean ge(String a, String b) { return a.compareTo(b) >= 1; }
    boolean other(int a, int b) { return Integer.compare(a, b) == 2; }
    boolean nan(double r, Object tag) { return Double.isNaN(r) || tag == null; }
    boolean n(Object x) { return Objects.equals(x, null); }
}

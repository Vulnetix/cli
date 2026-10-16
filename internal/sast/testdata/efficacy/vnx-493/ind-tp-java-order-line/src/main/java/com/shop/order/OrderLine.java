package com.shop.order;

import java.math.BigDecimal;

public class OrderLine {
    public String sku;
    public int quantity;
~>    public BigDecimal price;
~>    public double discountAmount;
~>    public String role = "customer";
    public final String currency = "EUR";
}

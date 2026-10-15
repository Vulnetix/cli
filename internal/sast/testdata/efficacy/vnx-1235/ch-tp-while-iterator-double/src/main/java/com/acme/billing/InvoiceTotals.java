package com.acme.billing;

import java.util.Iterator;
import java.util.List;

public class InvoiceTotals {

    public double total(List<LineItem> items) {
        Double total = 0.0;
        Iterator<LineItem> it = items.iterator();
        while (it.hasNext()) {
            LineItem li = it.next();
~>            total += li.getPrice() * li.getQuantity();
        }
        return total;
    }
}

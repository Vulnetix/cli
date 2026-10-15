package com.acme;

public class Order {
    private String id;
    private int qty;

    public String getId() {
~>        return getId();
    }

    public int getQty() {
~>        return this.getQty();
    }

    public void setId(String id) {
~>        setId(id);
    }
}

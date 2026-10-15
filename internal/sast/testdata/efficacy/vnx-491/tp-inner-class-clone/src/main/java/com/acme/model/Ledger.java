package com.acme.model;

public final class Ledger {
    public static class Entry implements Cloneable {
        int amount;

~>        public Entry clone() throws CloneNotSupportedException { return (Entry) super.clone(); }
    }
}

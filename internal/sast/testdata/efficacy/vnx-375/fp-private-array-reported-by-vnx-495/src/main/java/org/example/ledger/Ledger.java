package org.example.ledger;

import java.util.ArrayList;
import java.util.List;

// A public method returning a private array field is reported by VNX-495;
// VNX-375 keeps the collections, dates and non-public or non-private cases.
public class Ledger {
    private final long[] balances;
    private int[] checksums = new int[8];
    private final List<String> entries = new ArrayList<>();
    protected String[] tags;

    public Ledger(long[] balances) {
        this.balances = balances.clone();
    }

    public long[] getBalances() {
        return balances;
    }

    public int[] checksums() { return this.checksums; }

    public List<String> getEntries() {
~>        return entries;
    }

    public String[] getTags() {
~>        return tags;
    }
}

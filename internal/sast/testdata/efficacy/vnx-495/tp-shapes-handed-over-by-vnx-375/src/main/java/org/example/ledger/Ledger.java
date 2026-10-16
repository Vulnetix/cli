package org.example.ledger;

public class Ledger {
    private final long[] balances;
    private int[] checksums = new int[8];

    public Ledger(long[] balances) {
        this.balances = balances.clone();
    }

    public long[] getBalances() {
~>        return balances;
    }

~>    public int[] checksums() { return this.checksums; }
}

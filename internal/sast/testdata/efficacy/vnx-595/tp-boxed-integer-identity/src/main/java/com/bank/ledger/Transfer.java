package com.bank.ledger;

public class Transfer {
    boolean sameAccount(Integer fromId, Integer toId) {
~>        return fromId == toId;
    }

    void check(Account a, Account b) {
        Long left = a.getBalance();
        Long right = b.getBalance();
~>        if (left != right) {
            throw new IllegalStateException("mismatch");
        }
    }
}

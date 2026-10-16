package com.acme;

import java.math.BigDecimal;

public class WalletService {
    private final WalletRepository repo;

    public WalletService(WalletRepository repo) {
        this.repo = repo;
    }

    public void debit(String userId, BigDecimal amount) {
~>        synchronized (userId.intern()) {
            BigDecimal balance = repo.balance(userId);
            if (balance.compareTo(amount) < 0) {
                throw new IllegalStateException("insufficient funds");
            }
            repo.setBalance(userId, balance.subtract(amount));
        }
    }
}

package com.acme.ledger;

import java.util.concurrent.locks.ReentrantLock;

public class Account {
    private final ReentrantLock lock = new ReentrantLock();
    private long balance;

    public void withdraw(long amount) {
~>        lock.lock();
        if (amount > balance) {
            throw new InsufficientFundsException(balance, amount);
        }
        balance -= amount;
        lock.unlock();
    }
}

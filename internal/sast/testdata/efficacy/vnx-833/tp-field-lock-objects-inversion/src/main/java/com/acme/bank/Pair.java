package com.acme.bank;

public class Pair {
    public void swap(Account a, Account b) {
        synchronized(a.monitor){
~>            synchronized(b.monitor){
                long t = a.balance;
                a.balance = b.balance;
                b.balance = t;
            }
        }
    }

    public void reverse(Account a, Account b) {
        synchronized (b.monitor)
        {
~>            synchronized (a.monitor)
            {
                a.merge(b);
            }
        }
    }
}

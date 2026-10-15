package com.acme.bank;

public class Transfers {
    private final Object accountsLock = new Object();
    private final Object auditLock = new Object();

    public void transfer(Account from, Account to, long amount) {
        synchronized (accountsLock) {
            from.debit(amount);
            to.credit(amount);
~>            synchronized (auditLock) {
                audit.record(from, to, amount);
            }
        }
    }

    public void replayAudit() {
        synchronized (auditLock) {
            for (Entry e : audit.entries()) {
~>                synchronized (accountsLock) {
                    e.apply();
                }
            }
        }
    }
}

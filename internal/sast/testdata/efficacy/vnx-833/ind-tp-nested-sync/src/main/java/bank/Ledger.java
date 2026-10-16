package bank;

public class Ledger {
    private final Object accountsLock = new Object();
    private final Object auditLock = new Object();

    public void transfer(Account from, Account to, long amount) {
        synchronized (accountsLock) {
~>            synchronized (auditLock) {
                audit.record(from, to, amount);
            }
        }
    }

    public void replay(Entry e) {
        synchronized (auditLock) {
~>            synchronized (accountsLock) {
                e.apply();
            }
        }
    }
}

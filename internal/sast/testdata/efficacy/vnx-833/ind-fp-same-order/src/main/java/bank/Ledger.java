package bank;

public class Ledger {
    private final Object a = new Object();
    private final Object b = new Object();

    void one() {
        synchronized (a) {
            synchronized (b) {
                work();
            }
        }
    }

    void two() {
        synchronized (a) {
            synchronized (b) {
                other();
            }
        }
    }
}

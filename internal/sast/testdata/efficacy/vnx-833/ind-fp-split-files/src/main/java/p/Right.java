package p;

public class Right {
    void go() {
        synchronized (Locks.B) {
            synchronized (Locks.A) {
                run();
            }
        }
    }
}

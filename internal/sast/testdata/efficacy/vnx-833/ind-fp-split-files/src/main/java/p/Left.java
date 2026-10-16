package p;

public class Left {
    void go() {
        synchronized (Locks.A) {
            synchronized (Locks.B) {
                run();
            }
        }
    }
}

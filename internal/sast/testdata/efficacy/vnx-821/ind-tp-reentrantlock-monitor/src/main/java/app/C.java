package app;
import java.util.concurrent.locks.ReentrantLock;
public class C {
    private final ReentrantLock lock = new ReentrantLock();
    private int v;
    public void set(int x) {
~>        synchronized (lock) {
            v = x;
        }
    }
}

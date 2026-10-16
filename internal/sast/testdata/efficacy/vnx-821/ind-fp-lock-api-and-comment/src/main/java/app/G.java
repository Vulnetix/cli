package app;
import java.util.concurrent.locks.ReentrantLock;
public class G {
    private final ReentrantLock lock = new ReentrantLock();
    private int v;
    public void set(int x) {
        lock.lock();
        try { v = x; } finally { lock.unlock(); }
        // synchronized (new Object()) { v = 0; }
        String s = "synchronized (\"cache\")";
    }
}

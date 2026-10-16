package app;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;
@Service
public class Safe2 {
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<String, Integer> counts = new HashMap<>();
    private int total;
    public void bump(String k) {
        lock.lock();
        try {
            counts.merge(k, 1, Integer::sum);
            total++;
        } finally {
            lock.unlock();
        }
    }
}

package lk;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class Lookup {
    private static final Map<String, Integer> MAP;
    private static final List<String> NAMES = new ArrayList<>();
    private static final AtomicInteger COUNT;
    private static final ReentrantLock LOCK;
    private static final int[] TABLE;
    static {
        MAP = new HashMap<>();
        MAP.put("a", 1);
        COUNT = new AtomicInteger(0);
        LOCK = new ReentrantLock();
        TABLE = new int[256];
        Set<String> seen = new HashSet<>();
        StringBuilder sb = new StringBuilder();
    }
}

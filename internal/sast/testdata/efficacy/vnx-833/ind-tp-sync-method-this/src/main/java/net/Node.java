package net;

public class Node {
    private final Node peer;
    private final Object mon = new Object();

    public synchronized void push(Message m) {
~>        synchronized (mon) {
            queue.add(m);
        }
    }

    public void pull() {
        synchronized (mon) {
~>            synchronized (this) {
                queue.poll();
            }
        }
    }
}

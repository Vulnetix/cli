package bank;

public class Seq {
    private final Object a = new Object();
    private final Object b = new Object();

    void one() {
        synchronized (a) {
            x++;
        }
        synchronized (b) {
            y++;
        }
    }

    void two() {
        synchronized (b) {
            y--;
        }
        synchronized (a) {
            x--;
        }
    }
}

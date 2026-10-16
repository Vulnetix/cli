package app;

public class Init {
    private boolean ready;
    private String data;

    void ensure() {
        if (!ready) {
~>            synchronized (this) {
                if (!ready) {
                    data = compute();
                    ready = true;
                }
            }
        }
    }

    private String compute() { return "x"; }
}

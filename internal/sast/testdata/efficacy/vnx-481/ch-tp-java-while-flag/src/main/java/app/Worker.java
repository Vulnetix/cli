package app;

public class Worker {
    private boolean running;

    void loop() {
~>        while (running = true) {
            step();
        }
    }

    void step() {}
}

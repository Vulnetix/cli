package app;

import java.util.concurrent.atomic.AtomicReference;

public class Atom {
    private final AtomicReference<Atom> ref = new AtomicReference<>();

    Atom get() {
        Atom a = ref.get();
        if (a == null) {
            ref.compareAndSet(null, new Atom());
            a = ref.get();
        }
        return a;
    }

    enum Single { INSTANCE }
}

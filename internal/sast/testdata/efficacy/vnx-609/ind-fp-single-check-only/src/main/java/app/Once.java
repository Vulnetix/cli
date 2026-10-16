package app;

public class Once {
    private Object value;

    Object get() {
        if (value == null) {
            synchronized (this) {
                value = new Object();
            }
        }
        return value;
    }
}

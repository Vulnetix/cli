package app;

public class Registry {
    private static Registry instance;

    private Registry() {}

    public static Registry get() {
        if (instance == null) {
~>            synchronized (Registry.class) {
                if (instance == null) {
                    instance = new Registry();
                }
            }
        }
        return instance;
    }
}

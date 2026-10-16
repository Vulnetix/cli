package app;

public class Safe {
    private static volatile Safe instance;

    public static Safe get() {
        if (instance == null) {
            synchronized (Safe.class) {
                if (instance == null) {
                    instance = new Safe();
                }
            }
        }
        return instance;
    }
}

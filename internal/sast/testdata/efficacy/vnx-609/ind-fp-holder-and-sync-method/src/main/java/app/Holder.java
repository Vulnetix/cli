package app;

public class Holder {
    private static Holder lazy;

    private static class Inner {
        static final Holder INSTANCE = new Holder();
    }

    public static Holder viaHolder() {
        return Inner.INSTANCE;
    }

    public static synchronized Holder viaMethod() {
        if (lazy == null) {
            lazy = new Holder();
        }
        return lazy;
    }
}

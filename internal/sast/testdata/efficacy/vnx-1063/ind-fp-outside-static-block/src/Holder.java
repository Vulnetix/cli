package h;

public class Holder {
    private static final Client SHARED = new Client();
    private final Client mine;

    {
        mine = new Client();
    }

    public Holder() {
        Client c = new Client();
    }

    static Client build() {
        return new Client();
    }

    static {
        throw new IllegalStateException("never loaded");
    }
    // static { X = new Client(); }
    static final String DOC = "static { x = new Thing(); }";
}

package bank;

public class Misc {
    enum Mode { A, B }

    boolean m(Mode mode) { return mode == Mode.A; }
    boolean self(Misc other) { return other == this; }
    // Integer a, b; a == b is a bug
    String s = "Integer x == Integer y";
}

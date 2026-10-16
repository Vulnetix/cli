package util;

public class Legacy {
    boolean isZero(Integer value) {
~>        return value == new Integer(0);
    }

    boolean notFalse(Boolean b) {
~>        return b != new Boolean(false);
    }
}

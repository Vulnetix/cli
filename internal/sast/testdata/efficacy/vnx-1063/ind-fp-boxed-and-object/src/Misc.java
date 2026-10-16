package m;

public class Misc {
    static final Object MUTEX;
    static final Integer LIMIT;
    static final Long BIG;
    static {
        MUTEX = new Object();
        LIMIT = new Integer(5);
        BIG = new Long(7L);
    }
}

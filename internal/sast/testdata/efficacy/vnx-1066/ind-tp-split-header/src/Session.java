package m;

import java.io.Serializable;
import java.util.Comparator;

~>public final class Session implements
        Comparable<Session>,
        Serializable {
    private long id;
    public int compareTo(Session o) { return 0; }
}

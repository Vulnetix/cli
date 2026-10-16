package a;

public class Kid extends Base {
    public boolean same(Object o) {
        return o instanceof Base && ((Base) o).label() != null;
    }
}

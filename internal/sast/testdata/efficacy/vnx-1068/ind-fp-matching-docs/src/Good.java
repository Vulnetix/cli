package g;

import java.util.List;

public class Good<T> {
    /**
     * Adds an item.
     *
     * @param <T> element type
     * @param item the item
     * @param more extra items, may be omitted
     * @return true if added
     */
    public boolean add(T item, List<T> more) { return true; }

    /**
     * Only documents one of two.
     * @param a first
     */
    public void two(int a, int b) { }

    /** Inline {@return the count} and {@code @param nothing} mentions. */
    public int count() { return 0; }
}

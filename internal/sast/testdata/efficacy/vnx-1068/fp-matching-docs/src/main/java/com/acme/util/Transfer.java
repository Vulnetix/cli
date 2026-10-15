package com.acme.util;

import java.util.List;
import java.util.Map;

public class Transfer {
    /**
     * Moves money.
     *
     * @param from the debited account
     * @param to the credited account
     * @param amount amount in cents
     * @return the transfer id
     * @throws IllegalArgumentException when amount is negative
     */
    @Deprecated(since = "2.0")
    public long move(final Account from, @NonNull Account to,
            long amount) throws IllegalArgumentException {
        return 1;
    }

    /**
     * @param   rows   rows to index, keyed by name
     * @param lookup the lookup table
     */
    void index(Map<String, List<Integer>> rows, int[] lookup) {}

    /** Returns nothing. */
    void nop() {}
}

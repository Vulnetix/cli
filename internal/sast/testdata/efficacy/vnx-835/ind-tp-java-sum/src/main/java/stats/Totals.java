package stats;

public class Totals {
    public static long sum(int[] values, int count) {
        long total = 0;
        int i = 0;
~>        while (i < count) {
            total += values[i];
            log.trace("adding {}", values[i]);
        }
        return total;
    }
}

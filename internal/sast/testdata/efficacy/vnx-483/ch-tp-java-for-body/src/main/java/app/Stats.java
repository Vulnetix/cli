package app;

public class Stats {
    int sum(int[] values) {
        int total = 0;
        int count = 0;
        for (int v : values)
            total += v;
~>            count++;
        return total / count;
    }
}

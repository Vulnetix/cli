package stats;

public class Walk {
    static long a(int[] v, int n) {
        long t = 0;
        int i = 0;
        while (i < n) {
            t += v[i];
            i++;
        }
        return t;
    }

    static long b(int[] v, int n) {
        long t = 0;
        int i = 0;
        while (i < n) {
            t += v[i];
            i += 2;
        }
        return t;
    }

    static int c(int[] v, int n) {
        int i = 0;
        while (i != n) {
            i = next(i);
        }
        return i;
    }
}

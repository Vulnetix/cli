package app;

public class Retry {
    int attempt(int n) {
        if (n > 3)
            return -1;

        n++;
        while (n < 10)
            n *= 2;
        return n;
    }
}

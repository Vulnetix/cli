package com.acme.stats;

public class Mean {
    public static boolean usable(double[] samples) {
        double total = 0;
        for (double s : samples) {
            total += s;
        }
        double avg = total / samples.length;
        if (avg != avg) {
            return false;
        }
        return true;
    }
}

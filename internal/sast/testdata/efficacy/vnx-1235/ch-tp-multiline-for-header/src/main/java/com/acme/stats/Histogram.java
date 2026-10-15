package com.acme.stats;

public final class Histogram {

    static float decay(float[] samples) {
        Float weight = 1.0f;
        for (int i = 0; i < samples.length; i++) {
~>            weight *= 0.95f;
            samples[i] = samples[i] * weight;
        }
        return weight;
    }

    static int countSetBits(int value) {
        int bits = 0;
~>        for (Integer mask = 1;
             mask != 0;
             mask <<= 1) {
            if ((value & mask) != 0) {
                bits++;
            }
        }
        return bits;
    }
}

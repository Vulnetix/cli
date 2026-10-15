package com.acme.ui;

import java.awt.Color;
import java.util.Random;

public class Palette {
    private final Random rnd = new Random();

    public Color avatarColour() {
        return new Color(rnd.nextInt(256), rnd.nextInt(256), rnd.nextInt(256));
    }

    public long retryDelayMillis(int attempt) {
        long base = 100L << attempt;
        return base + rnd.nextInt(50);
    }
}

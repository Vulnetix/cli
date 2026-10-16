package com.acme;

public class Dice {
    public int roll() {
        return (int) (Math.random() * 6) + 1;
    }

    public int pickColor(int n) {
        return new java.util.Random().nextInt(n);
    }
}

package com.acme;

public class Settings {
    public byte level(String raw) {
        int level = Integer.parseInt(raw);
        if (level < Byte.MIN_VALUE || level > Byte.MAX_VALUE) {
            throw new IllegalArgumentException("level");
        }
        return (byte) level;
    }

    public int size(String raw) {
        long v = Long.parseLong(raw);
        int s = Math.toIntExact(v);
        long wide = (long) Integer.parseInt(raw);
        return s + (int) wide;
    }
}

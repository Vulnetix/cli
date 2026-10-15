package com.acme;

public class Sizes {
    String label(Size size) {
        String text = null;
        text = switch (size) {
            case SMALL -> "s";
            case LARGE -> "l";
        };
        return text.trim();
    }

    int weight(Size size) {
        return switch (size) {
            case SMALL -> 1;
            case LARGE -> 3;
        };
    }
}

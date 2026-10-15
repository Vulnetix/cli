package com.acme;

import java.util.Objects;
import java.util.Random;

public class Picker {
    int pick(String a, String b, int n) {
~>        int slot = Math.abs(Objects.hash(a, b)) % n;
~>        int r = Math.abs(new Random().nextInt()) % n;
        return slot + r;
    }
}

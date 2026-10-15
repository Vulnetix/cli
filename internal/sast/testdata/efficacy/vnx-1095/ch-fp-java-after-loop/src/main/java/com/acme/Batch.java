package com.acme;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class Batch {
    private final List<String> queue = new ArrayList<>();

    public List<String> flush() {
        List<String> out = new ArrayList<>();
        for (String s : queue) {
            out.add(s);
        }
        queue.clear();
        Iterator<String> it = out.iterator();
        while (it.hasNext()) {
            if (it.next().isEmpty()) it.remove();
        }
        return out;
    }
}

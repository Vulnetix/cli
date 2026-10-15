package com.acme;

import java.util.List;

public class Printer {
    public void printAll(List<String> lines) {
        for (String line : lines)
            System.out.println(line);
        lines.clear();
    }
}

package com.acme;

import java.util.Comparator;

public class ByName implements Comparator<Person> {
    @Override
    public int compare(Person a, Person b) {
        return a.name().compareTo(b.name());
    }

    public interface Ranked extends Comparable<Ranked> {
        int compareTo(Ranked other);
    }
}

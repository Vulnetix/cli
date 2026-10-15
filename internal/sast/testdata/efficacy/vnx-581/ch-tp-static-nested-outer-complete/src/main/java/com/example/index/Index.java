package com.example.index;

import java.util.Objects;

public class Index {
    private final String name;

    public Index(String name) {
        this.name = name;
    }

    static final class Term {
        final String text;

        Term(String text) {
            this.text = text;
        }

        @Override
~>        public boolean equals(Object o) {
            return o instanceof Term && ((Term) o).text.equals(text);
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Index && ((Index) o).name.equals(name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
}

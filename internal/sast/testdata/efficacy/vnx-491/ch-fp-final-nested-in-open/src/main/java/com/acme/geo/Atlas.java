package com.acme.geo;

public class Atlas {
    private final List<Page> pages = new ArrayList<>();

    public static final class Page implements Cloneable {
        int number;

        @Override
        public Page clone() {
            try {
                return (Page) super.clone();
            } catch (CloneNotSupportedException e) {
                throw new AssertionError(e);
            }
        }
    }
}

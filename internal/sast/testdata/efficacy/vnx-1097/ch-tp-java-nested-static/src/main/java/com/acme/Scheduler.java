package com.acme;

import java.util.PriorityQueue;

public class Scheduler {
    private final PriorityQueue<Task> queue = new PriorityQueue<>();

    static final class Task implements Comparable<Task> {
        final long due;
        final String name;

        Task(long due, String name) {
            this.due = due;
            this.name = name;
        }

        @Override
~>        public int compareTo(Task other) {
            return Long.compare(due, other.due);
        }
    }

    @Override
    public boolean equals(Object o) {
        return this == o;
    }
}

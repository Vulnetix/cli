package com.example.jobs;

public class Plugins {
    void loadAll(String[] names) {
        for (String name : names) {
            try {
                Class.forName(name);
~>            } catch (LinkageError err) {
                if (name.isEmpty()) {
                    continue;
                }
                System.err.println("skip " + name + ": " + err);
            } catch (ClassNotFoundException e) {
                System.err.println("missing " + name);
            }
        }
    }
}

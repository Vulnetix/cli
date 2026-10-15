package com.example.tools;

public class Remount {
    void remount() throws Exception {
        String[] command = {"su", "-c", "mount -o rw,remount /system"};
~>        Runtime.getRuntime().exec(command);
    }
}

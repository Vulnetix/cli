package com.example.tools;

public class Tools {
    void run() throws Exception {
        Runtime.getRuntime().exec("sum file.txt");
        Runtime.getRuntime().exec(new String[]{"sudo-helper", "status"});
        new ProcessBuilder("sh", "-c", "ls").start();
        String[] command = {"ls", "-la"};
        Runtime.getRuntime().exec(command);
    }
}

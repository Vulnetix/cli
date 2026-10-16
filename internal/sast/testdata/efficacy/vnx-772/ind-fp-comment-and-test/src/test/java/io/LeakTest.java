package io;

import java.io.*;

public class LeakTest {
    void leak(String p) throws IOException {
        FileInputStream in = new FileInputStream(p);
        in.read();
    }
}

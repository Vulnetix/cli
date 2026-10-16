package com.acme;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStream;

public final class Streams {
    private Streams() {}

    public static InputStream openData(File f) throws FileNotFoundException {
        FileInputStream in = new FileInputStream(f);
        return in;
    }

    public static BufferedReader reader(File f) throws FileNotFoundException {
        FileReader fr = new FileReader(f);
        return new BufferedReader(fr);
    }
}

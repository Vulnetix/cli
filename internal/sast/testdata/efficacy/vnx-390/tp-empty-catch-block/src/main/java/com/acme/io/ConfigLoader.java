package com.acme.io;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class ConfigLoader {
    public Properties load(String path) {
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(path)) {
            props.load(in);
~>        } catch (IOException e) {

        }
        return props;
    }

    public void pause(long ms) {
        try {
            Thread.sleep(ms);
        }
~>        catch (InterruptedException ex) {
        }
    }
}

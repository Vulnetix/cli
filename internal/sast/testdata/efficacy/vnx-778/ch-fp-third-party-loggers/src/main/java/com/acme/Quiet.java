package com.acme;

import java.util.logging.Level;
import java.util.logging.Logger;

public class Quiet {
    static {
        Logger.getLogger("org.apache.http").setLevel(Level.OFF);
    }
}

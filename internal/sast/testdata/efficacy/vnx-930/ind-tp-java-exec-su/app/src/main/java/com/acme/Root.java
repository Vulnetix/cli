package com.acme;

import java.io.IOException;

public class Root {
    public void remount() throws IOException {
~>        Runtime.getRuntime().exec("su -c mount -o remount,rw /system");
    }
}

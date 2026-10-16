package com.acme;

import java.io.IOException;

public class Backup {
    public Process copy(String dir) throws IOException {
~>        return Runtime.getRuntime().exec("cmd.exe /c xcopy " + dir + " D:\\backup /E");
    }
}

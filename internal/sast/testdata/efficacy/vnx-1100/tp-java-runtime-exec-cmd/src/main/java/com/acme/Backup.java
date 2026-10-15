package com.acme;

import java.io.IOException;

public class Backup {
    public Process run(String dir) throws IOException {
~>        return Runtime.getRuntime().exec("cmd.exe /c xcopy " + dir + " D:\\backup /E");
    }

    public Process list() throws IOException {
~>        return Runtime.getRuntime().exec(new String[] {"cmd", "/c", "dir"});
    }
}

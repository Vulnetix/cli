package com.example.tools;

import java.io.DataOutputStream;

public class RootShell {
    void run(String cmd) throws Exception {
~>        Process p = Runtime.getRuntime().exec("su");
        DataOutputStream os = new DataOutputStream(p.getOutputStream());
        os.writeBytes(cmd + "\n");
    }

    void runInline(String cmd) throws Exception {
~>        Runtime.getRuntime().exec(new String[] { "su", "-c", cmd });
~>        Runtime.getRuntime().exec("su -c " + cmd);
~>        Runtime.getRuntime().exec(new String[]{"/system/xbin/su", "-c", "reboot"});
    }
}

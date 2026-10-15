package com.acme.root;

public class Installer {
    void install(String apk) throws Exception {
~>        Process p = Runtime.getRuntime().exec(new String[] {
                "su", "-c", "pm install -r " + apk
        });
        p.waitFor();
    }
}

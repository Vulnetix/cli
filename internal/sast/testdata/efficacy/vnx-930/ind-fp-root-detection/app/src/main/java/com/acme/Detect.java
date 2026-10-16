package com.acme;

import java.io.File;

class Detect {
    boolean rooted() throws Exception {
        Process p = Runtime.getRuntime().exec("which su");
        boolean a = new File("/system/xbin/su").exists();
        Process q = Runtime.getRuntime().exec(new String[]{"ls", "/system/xbin/su"});
        return a;
    }
}

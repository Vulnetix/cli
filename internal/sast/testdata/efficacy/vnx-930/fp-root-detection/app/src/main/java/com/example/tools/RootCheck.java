package com.example.tools;

import java.io.File;

public class RootCheck {
    boolean rooted() throws Exception {
        if (new File("/system/app/Superuser.apk").exists()) return true;
        Process p = Runtime.getRuntime().exec(new String[] { "/system/bin/which", "su" });
        String[] paths = {"/sbin/su", "/system/bin/su", "/system/xbin/su"};
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return p.waitFor() == 0;
    }
}

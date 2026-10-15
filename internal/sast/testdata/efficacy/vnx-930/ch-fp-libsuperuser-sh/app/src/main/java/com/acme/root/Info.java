package com.acme.root;

import eu.chainfire.libsuperuser.Shell;
import java.util.List;

public class Info {
    List<String> props() {
        return Shell.SH.run("getprop ro.build.version.release");
    }

    boolean hasRoot() {
        return Shell.SU.available();
    }
}

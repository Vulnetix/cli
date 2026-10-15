package com.acme.root;

import eu.chainfire.libsuperuser.Shell;
import java.util.List;

public class Tweaks {
    List<String> apply(String governor) {
        if (!Shell.SU.available()) return null;
~>        return Shell.SU.run("echo " + governor + " > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
    }
}

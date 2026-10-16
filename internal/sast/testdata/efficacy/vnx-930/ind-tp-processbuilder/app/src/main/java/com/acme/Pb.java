package com.acme;

class Pb {
    Process go() throws Exception {
~>        ProcessBuilder pb = new ProcessBuilder(
            "su", "-c", "pm disable com.acme.x");
        return pb.start();
    }
}

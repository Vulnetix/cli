package com.acme.tools;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.util.JavacTask;
import com.sun.net.httpserver.HttpExchange;
import jdk.jfr.Event;
import jdk.jfr.Label;
import java.util.Base64;

public class Inspect {
    @Label("Inspection")
    static class InspectEvent extends Event {
    }

    public String encode(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }
}

package com.acme.ws;

public class Notes {
    // @WebMethod
    // public String debugDumpSessions() was removed in 2.0
    private static final String HELP = "<operation name=\"debugDumpSessions\"> is gone";

    public String describe() {
        return HELP;
    }
}

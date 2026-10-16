package com.acme.ws;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService
public class OpsEndpoint {

    @WebMethod(exclude = true)
    public String debugDumpState() {
        return state.snapshot();
    }

    // internalResetCache is only called from the scheduler
    public void internalResetCache() {
        cache.clear();
    }

    String dumpAllTokens() {
        return tokens.toString();
    }

    @WebMethod
    public String status() {
        String note = "see debugDumpSessions in the admin console";
        return note.isEmpty() ? "ok" : "ok";
    }
}

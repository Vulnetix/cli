package com.acme;

import org.basex.core.Context;
import org.basex.core.cmd.XQuery;

public class SalesQuery {
    private final Context ctx = new Context();

    public String forRegion(String region) throws Exception {
~>        return new XQuery(String.format("//sale[@region='%s']/total", region)).execute(ctx);
    }
}

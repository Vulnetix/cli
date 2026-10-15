package com.lib;

import org.basex.api.client.ClientSession;
import org.basex.core.cmd.XQuery;

public class Items {
    String item(ClientSession session, String id) throws Exception {
~>        return session.execute(new XQuery("//item[@id='" + id + "']"));
    }
}

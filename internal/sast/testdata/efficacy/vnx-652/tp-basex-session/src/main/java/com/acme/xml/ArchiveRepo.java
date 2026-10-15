package com.acme.xml;

import org.basex.api.client.ClientSession;
import org.basex.core.cmd.XQuery;

public class ArchiveRepo {
    private ClientSession session;

    public String byTitle(String title) throws Exception {
~>        return session.query("//doc[title='" + title + "']").execute();
    }

    public String raw(String filter) throws Exception {
~>        return session.execute(new XQuery("//doc[" + filter + "]"));
    }
}

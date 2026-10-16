package com.acme;

import net.sf.saxon.s9api.Processor;
import net.sf.saxon.s9api.XQueryCompiler;
import net.sf.saxon.s9api.XQueryExecutable;

public class UserLookup {
    private final Processor proc = new Processor(false);

    public XQueryExecutable find(String username) throws Exception {
        XQueryCompiler compiler = proc.newXQueryCompiler();
        String query = "doc('users.xml')/users/user"
            + "[name='" + username + "']";
~>        return compiler.compile(query);
    }
}

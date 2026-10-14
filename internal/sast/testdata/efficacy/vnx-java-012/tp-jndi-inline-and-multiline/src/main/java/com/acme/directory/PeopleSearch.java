package com.acme.directory;

import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;

public class PeopleSearch {
    private InitialDirContext dirContext;

    @GET
    public Object find(@QueryParam("mail") String mail, @QueryParam("ou") String ou) throws Exception {
        SearchControls sc = new SearchControls();
~>        Object byMail = dirContext.search("dc=acme,dc=com", "(mail=" + mail + ")", sc);
~>        Object byOu = dirContext.search(
                "ou=" + ou + ",dc=acme,dc=com",
                "(objectClass=person)",
                sc);
        return byMail;
    }
}

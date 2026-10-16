package com.acme;

public class JpqlNotes {
    // em.createQuery("from User where name='" + request.getParameter("n") + "'") is injectable
    String s = "session.createQuery(\"from X where y='\" + request.getParameter(\"y\") + \"'\")";
}

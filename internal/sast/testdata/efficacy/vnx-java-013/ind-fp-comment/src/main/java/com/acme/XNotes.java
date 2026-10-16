package com.acme;

public class XNotes {
    // xp.evaluate("//u[n='" + request.getParameter("n") + "']", doc) is injectable
    String s = "doc.selectNodes(\"//a[b='\" + request.getParameter(\"b\") + \"']\")";
}

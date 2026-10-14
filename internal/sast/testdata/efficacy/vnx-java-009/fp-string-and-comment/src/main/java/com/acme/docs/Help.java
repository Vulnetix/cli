package com.acme.docs;

import javax.servlet.http.HttpServletRequest;

public class Help {
    String explain(HttpServletRequest request) {
        String topic = request.getParameter("topic");
        // never write new File(topic) here, use the catalogue
        String text = "Do not call new File(" + "topic" + ") with user input";
        log("new FileInputStream(name) is unsafe for " + topic);
        return text;
    }

    void log(String s) {
    }
}

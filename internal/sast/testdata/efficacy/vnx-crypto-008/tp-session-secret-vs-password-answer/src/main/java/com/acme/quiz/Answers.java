package com.acme.quiz;

import javax.servlet.http.HttpServletRequest;

public class Answers {
    public boolean completed(HttpServletRequest request, String answerPwd) {
        String expectedSecret = (String) request.getSession().getAttribute("expectedSecret");
        // the stored secret is compared with the answer by equals()
~>        if (answerPwd.equals(expectedSecret)) {
            return true;
        }
        return false;
    }
}

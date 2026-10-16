package com.acme.quiz;

import javax.servlet.http.HttpServletRequest;

public class Answers {
    public boolean completed(HttpServletRequest request, String answerPwd) {
        String expectedSecret = (String) request.getSession().getAttribute("expectedSecret");
        // the secret compared by equals() is a VNX-CRYPTO-008 timing finding
        if (answerPwd.equals(expectedSecret)) {
            return true;
        }
        return false;
    }
}

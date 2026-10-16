package com.acme.quiz;

import org.apache.commons.codec.digest.DigestUtils;

public class HashCheck {
    boolean check(String answerPwd, String secret) {
        String md5Secret = DigestUtils.md5Hex(secret);
        // the supplied answer is compared with the digest by equals()
~>        if (answerPwd.equals(md5Secret)) {
            return true;
        }
        return false;
    }
}

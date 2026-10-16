package com.acme.quiz;

import org.apache.commons.codec.digest.DigestUtils;

public class HashCheck {
    boolean check(String answerPwd, String secret) {
        String md5Secret = DigestUtils.md5Hex(secret);
        // a timing finding of VNX-CRYPTO-008: the operand is named as a secret
        if (answerPwd.equals(md5Secret)) {
            return true;
        }
        return false;
    }
}

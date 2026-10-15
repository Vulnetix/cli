package com.acme.sms;

public class SmsConfig {
    TwilioRestClient client() {
        return new TwilioRestClient.Builder(
~>            "@@sample:SK[0-9a-f]{32}@@",
            secret)
            .accountSid(accountSid)
            .build();
    }
}

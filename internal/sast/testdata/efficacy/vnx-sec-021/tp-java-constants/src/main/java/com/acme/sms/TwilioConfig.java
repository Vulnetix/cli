package com.acme.sms;

import com.twilio.Twilio;

public final class TwilioConfig {
    static final String ACCOUNT_SID = "AC@@sample:[0-9a-f]{32}@@";
~>    static final String AUTH_TOKEN = "@@sample:[0-9a-f]{32}@@";

    static void init() {
        Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
    }
}

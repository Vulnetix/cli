package com.acme;

import com.slack.api.Slack;

public class Notifier {
    void post(String text) throws Exception {
        Slack.getInstance()
~>            .methods("@@sample:xoxb-[0-9]{12}-[0-9]{13}-[A-Za-z0-9]{24}@@")
            .chatPostMessage(r -> r.channel("#ops").text(text));
    }
}

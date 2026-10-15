package com.acme.mail;

import java.util.Date;
import java.util.Set;

public class Envelope {
    private Set<String> recipients;
    private Date sentAt;

~>    public void setRecipients(final Set<String> recipients) { this.recipients = recipients; }

~>    public void setSentAt(Date when) { sentAt = when; }

    public int size() { return recipients.size(); }
}

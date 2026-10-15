package com.acme.mail;

import com.sun.mail.smtp.SMTPTransport;
import com.sun.jersey.api.client.Client;
import com.sun.xml.bind.marshaller.NamespacePrefixMapper;
import com.sun.xml.ws.developer.JAXWSProperties;
import com.sun.jna.Pointer;

public class Mailer {
    private final Client client = Client.create();
}

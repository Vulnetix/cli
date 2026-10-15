package app;

public class Directory {
    public DirContext connect() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.SECURITY_PRINCIPAL, "cn=svc,dc=corp");
~>        env.put(Context.SECURITY_CREDENTIALS, "Ldap!Passw0rd");
        return new InitialDirContext(env);
    }

    public void mail(Message msg) throws MessagingException {
~>        Transport.send(msg, "mailer@corp.example", "M4il3r-secret");
~>        transport.connect("smtp.corp.example", "mailer", "M4il3r-secret");
    }
}

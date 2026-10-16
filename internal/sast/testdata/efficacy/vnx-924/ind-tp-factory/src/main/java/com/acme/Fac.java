package com.acme;
public class Fac {
    void f(String host) throws Exception {
~>        Socket t = SocketFactory.getDefault().createSocket(host, 7002);
        use(t);
    }
}

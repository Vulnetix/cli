package com.acme;

~>import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
~>import static jdk.internal.misc.VM.isBooted;

public class Xml {
    String enc(byte[] b) { return Base64.encode(b); }
}

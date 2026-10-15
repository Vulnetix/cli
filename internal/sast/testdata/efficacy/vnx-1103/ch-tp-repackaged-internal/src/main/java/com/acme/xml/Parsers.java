package com.acme.xml;

~>import com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl;
~>import @@sample:c[o]m[.][s]un[.]xm[l][.]i[n]te[r]na[l][.]b[i]nd[.]v2[.]Co[n]te[x]tF[a]ct[o]ry@@;
import javax.xml.parsers.DocumentBuilderFactory;

public final class Parsers {
    public static DocumentBuilderFactory factory() {
        return new DocumentBuilderFactoryImpl();
    }
}

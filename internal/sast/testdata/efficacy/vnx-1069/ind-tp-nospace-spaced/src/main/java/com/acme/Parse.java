package com.acme;
public class Parse {
    int num(String s) {
        int n = 0;
        try { n = Integer.parseInt(s); }
~>        catch(NumberFormatException ex) { }
        return n;
    }
    void sleepy() {
        try {
            Thread.sleep(50);
~>        } catch (InterruptedException e)
        {

        }
    }
}

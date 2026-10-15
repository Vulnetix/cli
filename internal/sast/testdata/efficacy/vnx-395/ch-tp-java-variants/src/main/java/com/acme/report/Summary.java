package com.acme.report;

public class Summary {
    public String owner(Account a) {
        try {
            return a.getOwner().getName();
~>        }catch(NullPointerException npe){
            return "unknown";
        }
    }

    public int size(Order o) {
        try {
            return o.getLines().size();
~>        } catch (IllegalStateException | java.lang.NullPointerException ex) {
            return 0;
        }
    }

    public String city(Customer c) {
        try {
            return c.address().city();
        }
~>        catch (
            NullPointerException e
        ) {
            return null;
        }
    }
}

package com.acme.bank;

public class Ledger
{
    private final Object ledger = new Object();
    private final Object audit = new Object();

    public void post(Entry e)
    {
        synchronized (ledger)
        {
~>            synchronized (audit)
            {
                write(e);
            }
        }
    }

    public void review()
    {
        synchronized (audit)
        {
~>            synchronized (ledger)
            {
                read();
            }
        }
    }

    private void write(Entry e) {}
    private void read() {}
}
